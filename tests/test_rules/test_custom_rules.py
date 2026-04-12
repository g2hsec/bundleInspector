"""Tests for custom regex rules.

This module intentionally includes fake secret-like strings so rule matching and
masking behavior can be regression-tested. They are sample values only.
"""

import json
import uuid
from pathlib import Path

from tests.fixtures.fake_secrets import FAKE_STRIPE_LIVE_SHORT, FAKE_STRIPE_TEST_SHORT
from bundleInspector.config import RuleConfig
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_path(name: str) -> Path:
    """Create a unique path under the workspace-local sandbox."""
    return TEST_TMP_ROOT / f"{uuid.uuid4().hex}_{name}"


def test_load_custom_source_rule_and_match():
    """Custom rules from JSON should be loaded and matched."""
    rule_path = _make_test_path("rules.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-internal-api",
                        "title": "Internal API Host",
                        "description": "Detect internal API URLs",
                        "category": "endpoint",
                        "severity": "high",
                        "confidence": "high",
                        "value_type": "internal_api",
                        "pattern": r"https://internal\.example\.com/api/[a-z]+",
                        "scope": "source",
                        "flags": ["i"],
                        "tags": ["custom", "internal"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'const api = "https://internal.example.com/api/users";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash123")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash123",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert any(f.rule_id == "custom-internal-api" for f in findings)
    finding = next(f for f in findings if f.rule_id == "custom-internal-api")
    assert finding.extracted_value == "https://internal.example.com/api/users"
    assert "custom_rule" in finding.tags


def test_load_custom_ast_pattern_rule_and_match():
    """Minimal declarative ast_pattern rules should match call expressions."""
    rule_path = _make_test_path("ast_rules.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-fetch-endpoint",
                        "title": "Literal fetch endpoint",
                        "description": "Detect literal fetch arguments",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_any_of": ["fetch"],
                                "args": [
                                    {
                                        "type": "LiteralString",
                                        "capture_as": "endpoint",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "endpoint": {
                                    "from_capture": "endpoint",
                                },
                                "method": {
                                    "static": "GET|UNKNOWN",
                                },
                            }
                        },
                        "evidence": {
                            "include_ast_path": True,
                        },
                        "tags": ["custom", "ast"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash456")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash456",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-fetch-endpoint")
    assert finding.extracted_value == "/api/users"
    assert finding.value_type == "endpoint"
    assert finding.metadata["extracted_fields"]["method"] == "GET|UNKNOWN"
    assert finding.metadata["ast_path"].startswith("Program")


def test_load_custom_rules_from_directory():
    """A rules directory should load all JSON/YAML rule files in filename order."""
    rules_dir = _make_test_path("rule_dir")
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "01_endpoints.yml").write_text(
        """
category: endpoints
rules:
  - id: END_FETCH_DIR
    title: "Directory fetch endpoint"
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint:
          from_capture: endpoint
""".strip(),
        encoding="utf-8",
    )
    (rules_dir / "02_secret.json").write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "SEC_TOKEN_DIR",
                        "title": "Directory token",
                        "category": "secret",
                        "pattern": r"sk_live_[A-Za-z0-9]{24}",
                        "scope": "source",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = f'''
fetch("/api/dir");
const token = "{FAKE_STRIPE_LIVE_SHORT}";
'''.strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-rule-dir")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-rule-dir",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rules_dir))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert any(f.rule_id == "END_FETCH_DIR" for f in findings)
    assert any(f.rule_id == "SEC_TOKEN_DIR" for f in findings)


def test_load_custom_rules_from_meta_file_uses_sibling_rules_directory():
    """A ruleset meta file should load shipped rule files from its sibling rules directory."""
    rules_root = _make_test_path("ruleset_pack")
    rules_root.mkdir(parents=True, exist_ok=True)
    (rules_root / "meta.yml").write_text(
        """
ruleset:
  id: "pack_default"
  version: "1.0.0"
""".strip(),
        encoding="utf-8",
    )
    rules_dir = rules_root / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "endpoints.yml").write_text(
        """
category: endpoints
rules:
  - id: END_FETCH_META
    title: "Meta fetch endpoint"
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint:
          from_capture: endpoint
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/meta");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ruleset-meta")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ruleset-meta",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rules_root / "meta.yml"))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert any(f.rule_id == "END_FETCH_META" for f in findings)


def test_shipped_example_ruleset_pack_matches_documented_examples():
    """The shipped example ruleset pack should load and match its documented endpoint/secret examples."""
    rule_path = Path(__file__).resolve().parents[2] / "examples" / "yaml-configs" / "rulesets" / "meta.yml"

    source = '''
const apiKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
fetch("/api/example?debug=1", {
  headers: {
    Authorization: "Bearer abcdefghijklmnopqrstuvwxyz123456"
  }
});
'''.strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-example-ruleset-pack")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-example-ruleset-pack",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert any(f.rule_id == "EP_FETCH_LITERAL" for f in findings)
    assert any(f.rule_id == "SEC_GENERIC_API_KEY_LITERAL" for f in findings)
    assert any(f.rule_id == "SEC_FETCH_AUTH_OPTION" for f in findings)


def test_ast_pattern_rule_resolves_identifier_and_normalizes_field():
    """Declarative AST rules should resolve identifier strings and normalize values."""
    rule_path = _make_test_path("ast_rules_identifier.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-fetch-identifier",
                        "title": "Identifier fetch endpoint",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_any_of": ["fetch"],
                                "args": [
                                    {
                                        "type": "IdentifierString",
                                        "capture_as": "endpoint",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "endpoint": {
                                    "from_capture": "endpoint",
                                }
                            }
                        },
                        "normalize": {
                            "endpoint": {
                                "strip_query": True,
                                "lowercase": True,
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'const API = "HTTPS://EXAMPLE.COM/API/USERS?TOKEN=abc"; fetch(API);'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash789")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash789",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-fetch-identifier")
    assert finding.extracted_value == "https://example.com/api/users"


def test_ast_pattern_new_expression_supports_constructor_match():
    """Declarative AST rules should also match constructor-style invocations."""
    rule_path = _make_test_path("ast_rules_new_expression.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-websocket-constructor",
                        "title": "Literal WebSocket endpoint",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "NewExpression",
                                "callee_any_of": ["WebSocket"],
                                "args": [
                                    {
                                        "type": "LiteralString",
                                        "capture_as": "endpoint",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "endpoint": {
                                    "from_capture": "endpoint",
                                }
                            }
                        },
                        "evidence": {
                            "include_ast_path": True,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'new WebSocket("wss://api.example.com/socket");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-new-expression")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-new-expression",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-websocket-constructor")
    assert finding.extracted_value == "wss://api.example.com/socket"
    assert finding.evidence.ast_node_type == "NewExpression"
    assert finding.metadata["ast_path"].startswith("Program")


def test_yaml_regex_matcher_inherits_top_level_category():
    """YAML regex matcher examples should inherit and normalize top-level categories."""
    rule_path = _make_test_path("domains.yml")
    rule_path.write_text(
        """
category: domains
rules:
  - id: DOM_INTERNAL_HOSTNAME
    title: "Internal-looking hostname found"
    severity: medium
    confidence: medium
    matcher:
      type: regex
      pattern: "(?i)\\b([a-z0-9\\-]+\\.)*(corp|internal|intra|local|lan)\\.[a-z]{2,}\\b"
      capture_as: domain
    extract:
      fields:
        indicator_type: { static: "domain" }
        value: { from_capture: domain }
""".strip(),
        encoding="utf-8",
    )

    source = 'const host = "api.internal.com";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-domain")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-domain",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "DOM_INTERNAL_HOSTNAME")
    assert finding.category.value == "domain"
    assert finding.extracted_value == "api.internal.com"
    assert finding.metadata["extracted_fields"]["indicator_type"] == "domain"


def test_yaml_regex_matcher_inherits_top_level_defaults_and_merges_tags():
    """Top-level rule defaults should propagate severity/confidence/tags and merge rule tags."""
    rule_path = _make_test_path("domains_defaults.yml")
    rule_path.write_text(
        """
category: domains
severity: high
confidence: medium
tags:
  - default-tag
rules:
  - id: DOM_DEFAULTED_INTERNAL_HOSTNAME
    title: "Inherited defaults hostname"
    tags:
      - rule-tag
    matcher:
      type: regex
      pattern: "(?i)\\b([a-z0-9\\-]+\\.)*(corp|internal|intra|local|lan)\\.[a-z]{2,}\\b"
      capture_as: domain
    extract:
      fields:
        value: { from_capture: domain }
""".strip(),
        encoding="utf-8",
    )

    source = 'const host = "api.internal.com";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-domain-defaults")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-domain-defaults",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "DOM_DEFAULTED_INTERNAL_HOSTNAME")
    assert finding.category.value == "domain"
    assert finding.severity.value == "high"
    assert finding.confidence.value == "medium"
    assert "default-tag" in finding.tags
    assert "rule-tag" in finding.tags


def test_yaml_rule_defaults_block_can_disable_rules_unless_overridden():
    """A top-level defaults block should apply enabled=false while allowing per-rule override."""
    rule_path = _make_test_path("defaults_enabled.yml")
    rule_path.write_text(
        """
defaults:
  category: secrets
  severity: medium
  confidence: high
  enabled: false
rules:
  - id: SEC_DISABLED_BY_DEFAULT
    title: "Disabled by default"
    pattern: "sk_live_[A-Za-z0-9]{24}"
  - id: SEC_OVERRIDE_ENABLED
    title: "Override enabled"
    enabled: true
    pattern: "sk_test_[A-Za-z0-9]{24}"
""".strip(),
        encoding="utf-8",
    )

    source = f'''
const liveKey = "{FAKE_STRIPE_LIVE_SHORT}";
const testKey = "{FAKE_STRIPE_TEST_SHORT}";
'''.strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-enabled-defaults")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-enabled-defaults",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert not any(f.rule_id == "SEC_DISABLED_BY_DEFAULT" for f in findings)
    finding = next(f for f in findings if f.rule_id == "SEC_OVERRIDE_ENABLED")
    assert finding.category.value == "secret"
    assert finding.severity.value == "medium"
    assert finding.confidence.value == "high"


def test_yaml_rule_defaults_block_merges_extract_normalize_and_evidence_defaults():
    """A defaults block should deep-merge declarative extract/normalize/evidence settings."""
    rule_path = _make_test_path("defaults_merge.yml")
    rule_path.write_text(
        """
defaults:
  category: endpoints
  evidence:
    include_ast_path: true
  extract:
    fields:
      source_label:
        static: "defaults"
  normalize:
    endpoint:
      strip_query: true
rules:
  - id: END_FETCH_DEFAULTS_MERGE
    title: "Defaults merge fetch endpoint"
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint:
          from_capture: endpoint
        method:
          static: "GET|UNKNOWN"
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users?view=full");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-defaults-merge")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-defaults-merge",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "END_FETCH_DEFAULTS_MERGE")
    assert finding.category.value == "endpoint"
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["source_label"] == "defaults"
    assert finding.metadata["extracted_fields"]["method"] == "GET|UNKNOWN"
    assert finding.metadata["ast_path"].startswith("Program")


def test_yaml_rule_defaults_block_merges_matcher_and_value_defaults():
    """A defaults block should deep-merge matcher settings and inherit value metadata defaults."""
    rule_path = _make_test_path("defaults_matcher_merge.yml")
    rule_path.write_text(
        """
defaults:
  category: endpoints
  description: "Inherited matcher defaults"
  value_type: "endpoint_url"
  matcher:
    type: ast_pattern
    pattern:
      kind: CallExpression
      callee_any_of:
        - "fetch"
rules:
  - id: END_FETCH_MATCHER_DEFAULTS
    title: "Defaults matcher fetch endpoint"
    matcher:
      pattern:
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint:
          from_capture: endpoint
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/defaults");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-defaults-matcher")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-defaults-matcher",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "END_FETCH_MATCHER_DEFAULTS")
    assert finding.category.value == "endpoint"
    assert finding.value_type == "endpoint_url"
    assert finding.description == "Inherited matcher defaults"
    assert finding.extracted_value == "/api/defaults"


def test_yaml_regex_rule_inherits_top_level_scope_flags_and_extract_group_defaults():
    """Top-level regex defaults should apply scope/flags/extract_group to legacy regex rules."""
    rule_path = _make_test_path("regex_top_level_defaults.yml")
    rule_path.write_text(
        """
category: secrets
scope: string_literal
extract_group: 1
flags:
  - i
rules:
  - id: SEC_LITERAL_SCOPE_DEFAULTS
    title: "Literal-only token via top-level regex defaults"
    pattern: "^(sk_[a-z0-9]{6})$"
""".strip(),
        encoding="utf-8",
    )

    source = '''
const liveKey = "SK_ABC123";
const note = "this should not match";
'''.strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-regex-top-level-defaults")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-regex-top-level-defaults",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_LITERAL_SCOPE_DEFAULTS")
    assert finding.category.value == "secret"
    assert finding.extracted_value == "SK_ABC123"


def test_yaml_regex_rule_defaults_block_merges_flags_and_inherits_source_scope():
    """Regex defaults block should merge flags and inherit source-scope matching behavior."""
    rule_path = _make_test_path("regex_defaults_block_flags.yml")
    rule_path.write_text(
        """
defaults:
  category: secrets
  scope: source
  extract_group: 1
  flags:
    - i
rules:
  - id: SEC_SOURCE_SCOPE_DEFAULTS
    title: "Source-scope regex via merged defaults"
    flags:
      - m
    pattern: "^(token:\\s+[a-z0-9]+)$"
""".strip(),
        encoding="utf-8",
    )

    source = '''
const banner = `
TOKEN: abc123
`;
'''.strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-regex-defaults-flags")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-regex-defaults-flags",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_SOURCE_SCOPE_DEFAULTS")
    assert finding.category.value == "secret"
    assert finding.extracted_value == "TOKEN: abc123"


def test_yaml_ast_pattern_variable_declarator_matches_secret_literal():
    """VariableDeclarator AST patterns from YAML examples should work."""
    rule_path = _make_test_path("secrets_ast.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_GENERIC_API_KEY_LITERAL
    title: "Suspicious hardcoded API key literal"
    severity: high
    confidence: medium
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_regex: "(?i)(api[_-]?key|secret|token|auth|private)"
        init:
          type: LiteralString
          regex: "^[A-Za-z0-9_\\-]{24,}$"
          capture_as: key
    extract:
      fields:
        secret_type: { static: "generic_key" }
        secret_value: { from_capture: key }
""".strip(),
        encoding="utf-8",
    )

    source = 'const apiKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-secret")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-secret",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_GENERIC_API_KEY_LITERAL")
    assert finding.category.value == "secret"
    assert finding.extracted_value == "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    assert finding.metadata["identifier_name"] == "apiKey"


def test_ast_pattern_call_expression_supports_regex_callee_match():
    """AST-pattern call rules should support regex matching on the short callee name."""
    rule_path = _make_test_path("ast_rules_call_regex.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-axios-short-name",
                        "title": "Axios GET endpoint",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_regex_any_of": ["^get$"],
                                "args": [
                                    {
                                        "type": "LiteralString",
                                        "regex": "^/api/[a-z]+$",
                                        "capture_as": "endpoint",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "endpoint": {"from_capture": "endpoint"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'axios.get("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-call-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-call-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-axios-short-name")
    assert finding.extracted_value == "/api/users"


def test_ast_pattern_call_expression_supports_identifier_name_arguments():
    """AST-pattern call rules should match identifier names directly, not only resolved string constants."""
    rule_path = _make_test_path("ast_rules_arg_identifier_name.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-fetch-identifier-name",
                        "title": "Identifier-name fetch argument",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_any_of": ["fetch"],
                                "args": [
                                    {
                                        "type": "IdentifierName",
                                        "any_of": ["endpointVar"],
                                        "capture_as": "arg_name",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "arg_name": {"from_capture": "arg_name"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = """
const endpointVar = "/api/users";
fetch(endpointVar);
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-arg-identifier-name")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-arg-identifier-name",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-fetch-identifier-name")
    assert finding.extracted_value == "endpointVar"


def test_ast_pattern_call_expression_supports_member_path_arguments():
    """AST-pattern call rules should match dotted member paths directly."""
    rule_path = _make_test_path("ast_rules_arg_member_path.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-client-member-path",
                        "title": "Member-path request argument",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_any_of": ["client.request"],
                                "args": [
                                    {
                                        "type": "MemberPath",
                                        "regex": "^routes\\.[a-z]+$",
                                        "capture_as": "route_ref",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "route_ref": {"from_capture": "route_ref"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'client.request(routes.users);'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-arg-member-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-arg-member-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-client-member-path")
    assert finding.extracted_value == "routes.users"


def test_ast_pattern_call_expression_supports_computed_member_path_arguments():
    """AST-pattern call rules should resolve constant-key computed member paths."""
    rule_path = _make_test_path("ast_rules_arg_computed_member_path.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-client-computed-member-path",
                        "title": "Computed member-path request argument",
                        "category": "endpoint",
                        "severity": "medium",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "CallExpression",
                                "callee_any_of": ["client.request"],
                                "args": [
                                    {
                                        "type": "MemberPath",
                                        "any_of": ["ROUTES.users"],
                                        "capture_as": "route_ref",
                                    }
                                ],
                            },
                        },
                        "extract": {
                            "fields": {
                                "route_ref": {"from_capture": "route_ref"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = """
const key = "users";
client.request(ROUTES[key]);
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-arg-computed-member-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-arg-computed-member-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-client-computed-member-path")
    assert finding.extracted_value == "ROUTES.users"


def test_ast_pattern_variable_declarator_supports_member_path_initializers():
    """AST-pattern init/right/value matchers should also support member-path extraction."""
    rule_path = _make_test_path("ast_rules_init_member_path.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-current-route-member-path",
                        "title": "Member-path variable initializer",
                        "category": "endpoint",
                        "severity": "low",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "VariableDeclarator",
                                "id_name_any_of": ["currentRoute"],
                                "init": {
                                    "type": "MemberPath",
                                    "any_of": ["ROUTES.users"],
                                    "capture_as": "route_ref",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "route_ref": {"from_capture": "route_ref"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'const currentRoute = ROUTES.users;'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-init-member-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-init-member-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-current-route-member-path")
    assert finding.extracted_value == "ROUTES.users"


def test_ast_pattern_variable_declarator_supports_computed_member_path_initializers():
    """AST-pattern value matchers should resolve constant-key computed member paths."""
    rule_path = _make_test_path("ast_rules_init_computed_member_path.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-current-route-computed-member-path",
                        "title": "Computed member-path variable initializer",
                        "category": "endpoint",
                        "severity": "low",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "VariableDeclarator",
                                "id_name_any_of": ["currentRoute"],
                                "init": {
                                    "type": "MemberPath",
                                    "any_of": ["ROUTES.users"],
                                    "capture_as": "route_ref",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "route_ref": {"from_capture": "route_ref"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = """
const routeKey = "users";
const currentRoute = ROUTES[routeKey];
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-init-computed-member-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-init-computed-member-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-current-route-computed-member-path")
    assert finding.extracted_value == "ROUTES.users"


def test_ast_pattern_variable_declarator_supports_exact_identifier_name_match():
    """AST-pattern variable rules should support exact identifier allowlists."""
    rule_path = _make_test_path("ast_rules_id_exact.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-token-declarator",
                        "title": "Auth token declarator",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "VariableDeclarator",
                                "id_name_any_of": ["authToken"],
                                "init": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = (
        'const authToken = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
        'const apiToken = "Bearer ZYXWVUTSRQPONMLKJIHGFEDC654321";'
    )
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-id-exact")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-id-exact",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    matched = [f for f in findings if f.rule_id == "custom-auth-token-declarator"]
    assert len(matched) == 1
    assert matched[0].extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert matched[0].metadata["identifier_name"] == "authToken"


def test_ast_pattern_assignment_expression_supports_exact_left_path_match():
    """AST-pattern assignment rules should support exact left-hand member paths."""
    rule_path = _make_test_path("ast_rules_assignment_exact.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-assignment",
                        "title": "Authorization assignment",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "AssignmentExpression",
                                "left_any_of": ["config.headers.Authorization"],
                                "right": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'config.headers.Authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-assignment-exact")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-assignment-exact",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-assignment")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["left_path"] == "config.headers.Authorization"


def test_ast_pattern_assignment_expression_supports_exact_computed_left_path_match():
    """AST-pattern assignment rules should resolve constant-key computed left-hand paths."""
    rule_path = _make_test_path("ast_rules_assignment_computed_left.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-assignment-computed",
                        "title": "Computed Authorization assignment",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "AssignmentExpression",
                                "left_any_of": ["config.headers.Authorization"],
                                "right": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = """
const headerName = "Authorization";
config.headers[headerName] = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-assignment-computed-left")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-assignment-computed-left",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-assignment-computed")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["left_path"] == "config.headers.Authorization"


def test_ast_pattern_assignment_expression_supports_regex_left_path_match():
    """AST-pattern assignment rules should support regex matching on left-hand member paths."""
    rule_path = _make_test_path("ast_rules_assignment_regex.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-assignment-regex",
                        "title": "Authorization assignment regex",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "AssignmentExpression",
                                "left_regex_any_of": ["(?i)authorization$"],
                                "right": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'request.headers.authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-assignment-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-assignment-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-assignment-regex")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["left_path"] == "request.headers.authorization"


def test_ast_pattern_property_supports_exact_property_path_match():
    """AST-pattern property rules should support exact object-literal property paths."""
    rule_path = _make_test_path("ast_rules_property_exact.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-property",
                        "title": "Authorization property literal",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "Property",
                                "property_path_any_of": ["headers.Authorization"],
                                "value": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = 'const options = { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-property-exact")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-property-exact",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-property")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["property_path"] == "headers.Authorization"


def test_ast_pattern_property_supports_exact_computed_property_path_match():
    """AST-pattern property rules should resolve constant-key computed object-literal paths."""
    rule_path = _make_test_path("ast_rules_property_computed_path.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-property-computed",
                        "title": "Computed Authorization property literal",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "Property",
                                "property_path_any_of": ["headers.Authorization"],
                                "value": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = """
const headerName = "Authorization";
const options = { headers: { [headerName]: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-property-computed-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-property-computed-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-property-computed")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["property_path"] == "headers.Authorization"


def test_ast_pattern_property_supports_regex_property_path_match():
    """AST-pattern property rules should support regex matching on nested object-literal paths."""
    rule_path = _make_test_path("ast_rules_property_regex.json")
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-auth-header-property-regex",
                        "title": "Authorization property regex",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "matcher": {
                            "type": "ast_pattern",
                            "pattern": {
                                "kind": "Property",
                                "property_path_regex_any_of": ["(?i)authorization$"],
                                "value": {
                                    "type": "LiteralString",
                                    "regex": "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$",
                                    "capture_as": "token",
                                },
                            },
                        },
                        "extract": {
                            "fields": {
                                "secret_value": {"from_capture": "token"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source = (
        'const options = { request: { headers: { authorization: '
        '"Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } } };'
    )
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-property-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-property-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "custom-auth-header-property-regex")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["property_path"] == "request.headers.authorization"


def test_yaml_semantic_assignment_matches_bearer_header_only():
    """Semantic AssignmentExpression rules should match only the intended header assignment."""
    rule_path = _make_test_path("secrets_semantic.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_BEARER
    title: "Bearer token assigned to Authorization header"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    any_of:
                      - "headers.Authorization"
                      - "config.headers.Authorization"
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
    evidence:
      include_ast_path: true
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'headers.Authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'headers.Authorization = "Token ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_AUTH_HEADER_BEARER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["left_path"] == "headers.Authorization"
    assert finding.metadata["ast_path"].startswith("Program")
    assert finding.metadata["masked_fields"]["secret_value"].startswith("Bearer")
    assert finding.metadata["masked_fields"]["secret_value"].endswith("3456")
    assert finding.metadata["extracted_fields"]["secret_value"] == finding.metadata["masked_fields"]["secret_value"]
    assert finding.metadata["extracted_fields"]["secret_value"] != finding.extracted_value
    assert not any(f.rule_id == "SEC_AUTH_HEADER_BEARER" for f in negative_findings)


def test_yaml_semantic_assignment_supports_exact_computed_left_path_matching():
    """Semantic AssignmentExpression rules should resolve constant-key computed left paths."""
    rule_path = _make_test_path("semantic_assignment_exact_computed_left.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_COMPUTED_LEFT
    title: "Bearer token assigned to computed Authorization header"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    any_of:
                      - "config.headers.Authorization"
                  left_capture_as: target_path
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        target_path: { from_capture: target_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
const headerName = "Authorization";
config.headers[headerName] = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-computed-left")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-left",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_AUTH_HEADER_COMPUTED_LEFT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["left_path"] == "config.headers.Authorization"
    assert finding.metadata["extracted_fields"]["target_path"] == "config.headers.Authorization"


def test_yaml_semantic_call_expression_matches_header_setter_only():
    """Semantic CallExpression rules should match intended call-site argument patterns only."""
    rule_path = _make_test_path("secrets_semantic_call.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_SETTER
    title: "Bearer token passed to headers.set"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
    evidence:
      include_ast_path: true
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const headerNames = { auth: "Authorization" };
    headers.set(headerNames.auth, "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");
    """
    negative_source = """
    const headerNames = { auth: "X-Trace" };
    headers.set(headerNames.auth, "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-call-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-call-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-call-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-call-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_AUTH_HEADER_SETTER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.evidence.ast_node_type == "CallExpression"
    assert finding.metadata["callee_path"] == "headers.set"
    assert finding.metadata["ast_path"].startswith("Program")
    assert finding.metadata["masked_fields"]["secret_value"].startswith("Bearer")
    assert finding.metadata["masked_fields"]["secret_value"].endswith("3456")
    assert not any(f.rule_id == "SEC_AUTH_HEADER_SETTER" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_object_argument_property():
    """Semantic CallExpression rules should match string properties inside object arguments."""
    rule_path = _make_test_path("secrets_semantic_object_arg.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_FETCH_AUTH_OPTION
    title: "Bearer token passed inside fetch options headers"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
    evidence:
      include_ast_path: true
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    fetch("/api/users", {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    fetch("/api/users", {
      headers: {
        Authorization: "Token ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_FETCH_AUTH_OPTION")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.evidence.ast_node_type == "CallExpression"
    assert finding.metadata["callee_path"] == "fetch"
    assert finding.metadata["ast_path"].startswith("Program")
    assert not any(f.rule_id == "SEC_FETCH_AUTH_OPTION" for f in negative_findings)


def test_yaml_semantic_new_expression_supports_regex_arg_match():
    """Semantic constructor rules should match constructor arguments like call expressions do."""
    rule_path = _make_test_path("endpoint_semantic_new_expression.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_WEBSOCKET_CONSTRUCTOR
    title: "WebSocket constructor endpoint"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: NewExpression
                  callee_any_of:
                    - "WebSocket"
              - regex_on_arg:
                  index: 0
                  pattern: "^wss://[^\\s]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        method: { static: "CONNECT|UNKNOWN" }
    evidence:
      include_ast_path: true
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'new WebSocket("wss://api.example.com/socket");'
    negative_source = 'new WebSocket("https://www.example.com/docs");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-new-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-new-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-new-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-new-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_WEBSOCKET_CONSTRUCTOR")
    assert finding.extracted_value == "wss://api.example.com/socket"
    assert finding.evidence.ast_node_type == "NewExpression"
    assert finding.metadata["callee_path"] == "WebSocket"
    assert finding.metadata["ast_path"].startswith("Program")
    assert not any(f.rule_id == "ENDPOINT_WEBSOCKET_CONSTRUCTOR" for f in negative_findings)


def test_yaml_semantic_new_expression_matches_object_argument_property():
    """Semantic constructor rules should inspect string properties inside constructor options."""
    rule_path = _make_test_path("secrets_semantic_new_expression_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_REQUEST_CONSTRUCTOR_AUTH
    title: "Bearer token passed to Request constructor"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: NewExpression
                  callee_any_of:
                    - "Request"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
    evidence:
      include_ast_path: true
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    new Request("/api/users", {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    new Request("/api/users", {
      headers: {
        Authorization: "Token ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-new-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-new-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-new-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-new-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_REQUEST_CONSTRUCTOR_AUTH")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.evidence.ast_node_type == "NewExpression"
    assert finding.metadata["callee_path"] == "Request"
    assert finding.metadata["ast_path"].startswith("Program")
    assert not any(f.rule_id == "SEC_REQUEST_CONSTRUCTOR_AUTH" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_identifier_backed_object_argument_property():
    """Semantic object-argument matchers should resolve identifier and member-backed config objects."""
    rule_path = _make_test_path("secrets_semantic_object_identifier.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_OPTION
    title: "Bearer token passed inside request config headers"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const request = {
      options: {
        headers: {
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      }
    };
    client.request(request.options);
    """
    negative_source = """
    const request = {
      options: {
        headers: {
          Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      }
    };
    client.request(request.options);
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-identifier-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-identifier-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-identifier-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-identifier-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_OPTION")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.evidence.ast_node_type == "CallExpression"
    assert finding.metadata["callee_path"] == "client.request"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_OPTION" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_array_selected_object_argument_property():
    """Semantic object-argument matchers should resolve array-selected config objects."""
    rule_path = _make_test_path("secrets_semantic_object_array.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_OPTION_ARRAY
    title: "Bearer token passed inside array-selected request config"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_type: { static: "bearer_token" }
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const requests = [
      { headers: { Trace: "ignore" } },
      { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
    ];
    const requestIndex = 1;
    client.request(requests[requestIndex]);
    """
    negative_source = """
    const requests = [
      { headers: { Trace: "ignore" } },
      { headers: { Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
    ];
    const requestIndex = 1;
    client.request(requests[requestIndex]);
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-array-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-array-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-array-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-array-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_OPTION_ARRAY")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_OPTION_ARRAY" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_helper_returned_argument_string():
    """Semantic argument matchers should resolve helper-returned string values."""
    rule_path = _make_test_path("secrets_semantic_helper_arg.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_HELPER_ARG
    title: "Bearer token passed via helper-returned arg"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function authHeader() {
      return "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";
    }
    headers.set("Authorization", authHeader());
    """
    negative_source = """
    function authHeader() {
      return "Token ABCDEFGHIJKLMNOPQRSTUVWX123456";
    }
    headers.set("Authorization", authHeader());
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-arg-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-arg-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-arg-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-arg-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_AUTH_HEADER_HELPER_ARG")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_AUTH_HEADER_HELPER_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_helper_returned_object_argument_property():
    """Semantic object-argument matchers should resolve helper-returned config objects."""
    rule_path = _make_test_path("secrets_semantic_helper_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_HELPER_OBJECT
    title: "Bearer token passed via helper-returned config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestConfig() {
      return {
        headers: {
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
    }
    client.request(requestConfig());
    """
    negative_source = """
    function requestConfig() {
      return {
        headers: {
          Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
    }
    client.request(requestConfig());
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_HELPER_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_HELPER_OBJECT" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_helper_returned_object_argument_property_with_computed_path():
    """Semantic object-argument matchers should resolve computed property paths inside helper-returned config objects."""
    rule_path = _make_test_path("secrets_semantic_helper_object_computed_path.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_HELPER_OBJECT_COMPUTED_PATH
    title: "Bearer token passed via helper-returned computed config path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_regex_any_of:
                    - "(?i)^headers\\.authorization$"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    const headerName = "Authorization";
    function requestConfig() {
      const config = {
        headers: {
          [headerName]: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
      return config;
    }
    client.request(requestConfig());
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-helper-object-computed-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-object-computed-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_HELPER_OBJECT_COMPUTED_PATH")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_matches_object_argument_property_with_spread_override():
    """Semantic object-argument matchers should resolve spread config properties with later overrides."""
    rule_path = _make_test_path("secrets_semantic_object_spread.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_FETCH_AUTH_OPTION_SPREAD
    title: "Bearer token passed inside spread fetch options headers"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const baseOptions = {
      headers: {
        Authorization: "Token SHOULD_NOT_MATCH",
        Trace: "ignore"
      }
    };
    fetch("/api/users", {
      ...baseOptions,
      headers: {
        ...baseOptions.headers,
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    const baseOptions = {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456",
        Trace: "ignore"
      }
    };
    fetch("/api/users", {
      ...baseOptions,
      headers: {
        ...baseOptions.headers,
        Authorization: "Token SHOULD_NOT_MATCH"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-spread-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-spread-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-spread-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-spread-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_FETCH_AUTH_OPTION_SPREAD")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_FETCH_AUTH_OPTION_SPREAD" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_object_property_path_any_of():
    """Semantic object-argument matchers should support multiple exact property paths."""
    rule_path = _make_test_path("secrets_semantic_object_path_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_ANY_OF
    title: "Bearer token passed via one of several exact config paths"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_any_of:
                    - "headers.Authorization"
                    - "auth.token"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    client.request({
      auth: {
        token: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    client.request({
      headers: {
        "X-Api-Key": "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-path-any-of-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-any-of-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-path-any-of-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-any-of-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_ANY_OF")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_PATH_ANY_OF" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_object_property_path_contains_any_of():
    """Semantic object-argument matchers should support substring-matched property paths."""
    rule_path = _make_test_path("secrets_semantic_object_path_contains_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_CONTAINS
    title: "Bearer token passed via auth-like property path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_contains_any_of:
                    - "Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    client.request({
      meta: {
        Token: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(
        positive_result.ast,
        "file:///bundle.js",
        "hash-semantic-object-path-contains-positive",
    )
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-path-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_CONTAINS")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_PATH_CONTAINS" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_not_object_property_path_any_of():
    """Semantic object-argument matchers should support exact denylisted property paths."""
    rule_path = _make_test_path("secrets_semantic_object_not_path_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_NOT_PATH_ANY_OF
    title: "Bearer token outside denylisted config paths"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_any_of:
                  index: 0
                  not_path_any_of:
                    - "meta.Authorization"
                  any_of:
                    - "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    client.request({
      meta: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-any-of-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-any-of-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-any-of-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-any-of-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_ANY_OF")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_ANY_OF" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_not_object_property_path_contains_any_of():
    """Semantic object-argument matchers should support substring denylisted property paths."""
    rule_path = _make_test_path("secrets_semantic_object_not_path_contains_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_NOT_PATH_CONTAINS
    title: "Bearer token outside denylisted path fragments"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  not_path_contains_any_of:
                    - "meta"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    client.request({
      meta: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_CONTAINS")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_CONTAINS" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_not_object_property_path_regex_any_of():
    """Semantic object-argument matchers should support regex denylisted property paths."""
    rule_path = _make_test_path("secrets_semantic_object_not_path_regex_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_NOT_PATH_REGEX
    title: "Bearer token outside regex-denylisted config paths"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_contains_any_of:
                  index: 0
                  not_path_regex_any_of:
                    - "^meta\\."
                  any_of:
                    - "Bearer "
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    client.request({
      meta: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-regex-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-regex-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-not-path-regex-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-not-path-regex-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_REGEX")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_NOT_PATH_REGEX" for f in negative_findings)


def test_yaml_semantic_call_expression_exact_object_property_can_capture_matched_path():
    """Exact object-property matchers should expose the matched property path as a capture."""
    rule_path = _make_test_path("secrets_semantic_object_path_capture_exact.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_CAPTURE_EXACT
    title: "Capture exact matched config path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_any_of:
                  index: 0
                  path_any_of:
                    - "headers.Authorization"
                    - "auth.token"
                  any_of:
                    - "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-capture-exact")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-capture-exact",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_CAPTURE_EXACT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_exact_object_property_can_capture_computed_matched_path():
    """Exact object-property matchers should capture computed object-argument paths."""
    rule_path = _make_test_path("secrets_semantic_object_path_capture_exact_computed.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_CAPTURE_EXACT_COMPUTED
    title: "Capture exact-matched computed config path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_any_of:
                  index: 0
                  path_any_of:
                    - "headers.Authorization"
                  any_of:
                    - "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    const headerName = "Authorization";
    client.request({
      headers: {
        [headerName]: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-capture-exact-computed")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-capture-exact-computed",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_CAPTURE_EXACT_COMPUTED")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_contains_object_property_can_capture_matched_path():
    """Contains object-property matchers should expose the matched property path as a capture."""
    rule_path = _make_test_path("secrets_semantic_object_path_capture_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_CAPTURE_CONTAINS
    title: "Capture contains-matched config path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_contains_any_of:
                  index: 0
                  path_contains_any_of:
                    - "Authorization"
                  any_of:
                    - "Bearer "
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-capture-contains")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-capture-contains",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_CAPTURE_CONTAINS")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_regex_object_property_can_capture_matched_path():
    """Regex object-property matchers should expose the matched property path as a capture."""
    rule_path = _make_test_path("secrets_semantic_object_path_capture_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_PATH_CAPTURE_REGEX
    title: "Capture regex-matched config path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_regex_any_of:
                    - "Authorization$"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    client.request({
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-capture-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-capture-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_PATH_CAPTURE_REGEX")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_exact_arg_can_capture_matched_index():
    """Exact arg matchers should expose the matched argument index as a capture."""
    rule_path = _make_test_path("semantic_arg_index_capture_exact.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_ARG_INDEX_CAPTURE_EXACT
    title: "Capture exact arg index"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - arg_any_of:
                  index: 0
                  any_of:
                    - "/api/users"
                  index_capture_as: matched_index
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        matched_index: { from_capture: matched_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-arg-index-exact")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-index-exact",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_ARG_INDEX_CAPTURE_EXACT")
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["matched_index"] == "0"


def test_yaml_semantic_call_expression_contains_arg_can_capture_matched_index():
    """Contains arg matchers should expose the matched argument index as a capture."""
    rule_path = _make_test_path("semantic_arg_index_capture_contains.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_ARG_INDEX_CAPTURE_CONTAINS
    title: "Capture contains arg index"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - arg_contains_any_of:
                  index: 0
                  any_of:
                    - "/api/"
                  index_capture_as: matched_index
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        matched_index: { from_capture: matched_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users?view=full");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-arg-index-contains")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-index-contains",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_ARG_INDEX_CAPTURE_CONTAINS")
    assert finding.extracted_value == "/api/users?view=full"
    assert finding.metadata["extracted_fields"]["matched_index"] == "0"


def test_yaml_semantic_call_expression_regex_arg_can_capture_matched_index():
    """Regex arg matchers should expose the matched argument index as a capture."""
    rule_path = _make_test_path("semantic_arg_index_capture_regex.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_ARG_INDEX_CAPTURE_REGEX
    title: "Capture regex arg index"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  index_capture_as: matched_index
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        matched_index: { from_capture: matched_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-arg-index-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-index-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_ARG_INDEX_CAPTURE_REGEX")
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["matched_index"] == "0"


def test_yaml_semantic_call_expression_regex_arg_supports_index_any_of():
    """Regex arg matchers should support matching across multiple candidate indices."""
    rule_path = _make_test_path("semantic_arg_index_any_of_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ARG_INDEX_ANY_OF_REGEX
    title: "Match bearer token across multiple arg positions"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "sendRequest"
              - regex_on_arg:
                  index_any_of:
                    - 0
                    - 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  index_capture_as: matched_index
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        matched_index: { from_capture: matched_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'sendRequest("/api/users", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-arg-index-any-of-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-index-any-of-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_ARG_INDEX_ANY_OF_REGEX")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_index"] == "1"


def test_yaml_semantic_call_expression_object_property_can_capture_matched_index():
    """Object-property matchers should expose the matched options-argument index as a capture."""
    rule_path = _make_test_path("semantic_object_arg_index_capture.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_OBJECT_ARG_INDEX_CAPTURE
    title: "Capture object-arg index"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  index_capture_as: matched_index
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
        matched_index: { from_capture: matched_index }
""".strip(),
        encoding="utf-8",
    )

    source = """
    fetch("/api/users", {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-arg-index")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-arg-index",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_OBJECT_ARG_INDEX_CAPTURE")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_index"] == "1"


def test_yaml_semantic_call_expression_object_property_supports_index_any_of_and_path_capture():
    """Object-property matchers should support matching across multiple candidate argument indices."""
    rule_path = _make_test_path("semantic_object_arg_index_any_of.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_OBJECT_ARG_INDEX_ANY_OF
    title: "Capture object-arg match across multiple positions"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "sendRequest"
              - regex_on_object_arg_property:
                  index_any_of:
                    - 1
                    - 2
                  path_regex_any_of:
                    - "(?i)^headers\\.authorization$"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  index_capture_as: matched_index
                  path_capture_as: matched_path
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        matched_index: { from_capture: matched_index }
        matched_path: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    sendRequest(
      "/api/users",
      { trace: "ignore" },
      { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
    );
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None
    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-arg-index-any-of")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-arg-index-any-of",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_OBJECT_ARG_INDEX_ANY_OF")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["matched_index"] == "2"
    assert finding.metadata["extracted_fields"]["matched_path"] == "headers.Authorization"


def test_yaml_semantic_call_expression_matches_helper_returned_spread_object_argument_property():
    """Semantic object-argument matchers should resolve helper-returned spread config objects."""
    rule_path = _make_test_path("secrets_semantic_helper_spread_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_HELPER_SPREAD_OBJECT
    title: "Bearer token passed via helper-returned spread config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestConfig() {
      const base = {
        headers: {
          Authorization: "Token SHOULD_NOT_MATCH",
          Trace: "ignore"
        }
      };
      return {
        ...base,
        headers: {
          ...base.headers,
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
    }
    client.request(requestConfig());
    """
    negative_source = """
    function requestConfig() {
      const base = {
        headers: {
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456",
          Trace: "ignore"
        }
      };
      return {
        ...base,
        headers: {
          ...base.headers,
          Authorization: "Token SHOULD_NOT_MATCH"
        }
      };
    }
    client.request(requestConfig());
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-spread-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-spread-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-spread-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-spread-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_HELPER_SPREAD_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_HELPER_SPREAD_OBJECT" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_block_helper_returned_object_argument_property():
    """Semantic object-argument matchers should resolve block-bodied helper configs with local arrays."""
    rule_path = _make_test_path("secrets_semantic_helper_block_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_BLOCK_HELPER_OBJECT
    title: "Bearer token passed via block helper config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestConfig(index) {
      const configs = [
        { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } },
        { headers: { Authorization: "Bearer ZXCVBNMASDFGHJKLQWERTY12345678" } }
      ];
      return configs[index];
    }
    client.request(requestConfig(0));
    """
    negative_source = """
    function requestConfig(index) {
      const configs = [
        { headers: { Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
      ];
      return configs[index];
    }
    client.request(requestConfig(0));
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-block-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-block-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-block-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-block-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_BLOCK_HELPER_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_BLOCK_HELPER_OBJECT" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_block_helper_returned_object_alias_property():
    """Semantic object-argument matchers should resolve aliased local config objects in block helpers."""
    rule_path = _make_test_path("secrets_semantic_helper_block_alias_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_BLOCK_ALIAS_OBJECT
    title: "Bearer token passed via aliased block helper config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestConfig(index) {
      const configs = [
        { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
      ];
      const cfg = configs[index];
      return cfg;
    }
    client.request(requestConfig(0));
    """
    negative_source = """
    function requestConfig(index) {
      const configs = [
        { headers: { Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
      ];
      const cfg = configs[index];
      return cfg;
    }
    client.request(requestConfig(0));
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-block-alias-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-block-alias-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-block-alias-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-block-alias-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_BLOCK_ALIAS_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_BLOCK_ALIAS_OBJECT" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_object_method_returned_argument_string():
    """Semantic argument matchers should resolve object-method-returned strings."""
    rule_path = _make_test_path("secrets_semantic_helper_method_arg.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_HELPER_METHOD_ARG
    title: "Bearer token passed via object-method arg"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const helpers = {
      authHeader() {
        return "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";
      }
    };
    headers.set("Authorization", helpers.authHeader());
    """
    negative_source = """
    const helpers = {
      authHeader() {
        return "Token ABCDEFGHIJKLMNOPQRSTUVWX123456";
      }
    };
    headers.set("Authorization", helpers.authHeader());
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-method-arg-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-arg-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-method-arg-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-arg-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_AUTH_HEADER_HELPER_METHOD_ARG")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_AUTH_HEADER_HELPER_METHOD_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_block_object_method_returned_object_argument_property():
    """Semantic object-argument matchers should resolve block-bodied object-method configs with local arrays."""
    rule_path = _make_test_path("secrets_semantic_helper_method_block_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_BLOCK_HELPER_METHOD_OBJECT
    title: "Bearer token passed via block object-method config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const helpers = {
      requestConfig(index) {
        const configs = [
          { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } },
          { headers: { Authorization: "Bearer ZXCVBNMASDFGHJKLQWERTY12345678" } }
        ];
        return configs[index];
      }
    };
    client.request(helpers.requestConfig(0));
    """
    negative_source = """
    const helpers = {
      requestConfig(index) {
        const configs = [
          { headers: { Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }
        ];
        return configs[index];
      }
    };
    client.request(helpers.requestConfig(0));
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-method-block-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-block-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-method-block-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-block-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_BLOCK_HELPER_METHOD_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_BLOCK_HELPER_METHOD_OBJECT" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_object_method_returned_object_argument_property():
    """Semantic object-argument matchers should resolve object-method-returned config objects."""
    rule_path = _make_test_path("secrets_semantic_helper_method_object.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_HELPER_METHOD_OBJECT
    title: "Bearer token passed via object-method config object"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const helpers = {
      requestConfig() {
        return {
          headers: {
            Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
          }
        };
      }
    };
    client.request(helpers.requestConfig());
    """
    negative_source = """
    const helpers = {
      requestConfig() {
        return {
          headers: {
            Trace: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
          }
        };
      }
    };
    client.request(helpers.requestConfig());
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-helper-method-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-helper-method-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-helper-method-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTH_HELPER_METHOD_OBJECT")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert not any(f.rule_id == "SEC_CLIENT_AUTH_HELPER_METHOD_OBJECT" for f in negative_findings)


def test_yaml_semantic_assignment_supports_negative_regex_guard():
    """Semantic AssignmentExpression rules should support excluding matched values with negative guards."""
    rule_path = _make_test_path("secrets_semantic_not_right.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_LIVE_ONLY
    title: "Bearer token assigned to Authorization header excluding test values"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    any_of:
                      - "headers.Authorization"
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_right:
                  pattern: "(?i)^Bearer\\s+(test|demo)-"
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'headers.Authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'headers.Authorization = "Bearer test-ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-not-right-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-right-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-not-right-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-right-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_AUTH_HEADER_LIVE_ONLY" for f in positive_findings)
    assert not any(f.rule_id == "SEC_AUTH_HEADER_LIVE_ONLY" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_negative_arg_guard():
    """Semantic CallExpression rules should support excluding matched arguments with negative guards."""
    rule_path = _make_test_path("secrets_semantic_not_arg.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_AUTH_HEADER_SETTER_LIVE_ONLY
    title: "Bearer token passed to headers.set excluding test values"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+(test|demo)-"
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'headers.set("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    negative_source = 'headers.set("Authorization", "Bearer demo-ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-not-arg-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-arg-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-not-arg-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-arg-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_AUTH_HEADER_SETTER_LIVE_ONLY" for f in positive_findings)
    assert not any(f.rule_id == "SEC_AUTH_HEADER_SETTER_LIVE_ONLY" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_negative_object_property_guard():
    """Semantic object-argument matchers should support excluding property values with negative guards."""
    rule_path = _make_test_path("secrets_semantic_not_object_arg.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_FETCH_AUTH_OPTION_LIVE_ONLY
    title: "Bearer token passed inside fetch options headers excluding demo values"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+(test|demo)-"
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    fetch("/api/users", {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    negative_source = """
    fetch("/api/users", {
      headers: {
        Authorization: "Bearer demo-ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-not-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-not-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-not-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_FETCH_AUTH_OPTION_LIVE_ONLY" for f in positive_findings)
    assert not any(f.rule_id == "SEC_FETCH_AUTH_OPTION_LIVE_ONLY" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_object_property_path_regex_with_helper_return():
    """Semantic object-argument matchers should support regex path filters on helper-returned config objects."""
    rule_path = _make_test_path("semantic_object_arg_property_path_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_REGEX_PATH_HELPER
    title: "Bearer token passed via helper-returned config object with regex path filter"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_regex_any_of:
                    - "(?i)^headers\\.(authorization|x-api-key)$"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig() {
      return {
        headers: {
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
    }
    client.request(requestConfig());
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_REGEX_PATH_HELPER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"


def test_yaml_semantic_call_expression_skips_object_property_when_path_regex_does_not_match():
    """Semantic object-argument path regex filters should not match unrelated property paths."""
    rule_path = _make_test_path("semantic_object_arg_property_path_regex_negative.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_REGEX_PATH_NEGATIVE
    title: "Bearer token passed via regex-matched config path only"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path_regex_any_of:
                    - "(?i)^headers\\.authorization$"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig() {
      return {
        meta: {
          Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        }
      };
    }
    client.request(requestConfig());
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-path-regex-negative")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-path-regex-negative",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert not any(f.rule_id == "SEC_CLIENT_AUTH_REGEX_PATH_NEGATIVE" for f in findings)


def test_yaml_semantic_assignment_supports_regex_left_match():
    """Semantic assignment rules should support regex matching on member paths."""
    rule_path = _make_test_path("semantic_left_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_AUTH_HEADER
    title: "Bearer token assigned to any Authorization-like header path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    regex_any_of:
                      - "(?i)authorization$"
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = 'request.headers.Authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-left-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-left-regex",
        source_content=source,
        is_first_party=True,
    )

    findings = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    findings.register_defaults()
    result = findings.analyze(ir, context)

    assert any(f.rule_id == "SEC_ANY_AUTH_HEADER" for f in result)


def test_yaml_semantic_assignment_supports_contains_left_match():
    """Semantic assignment rules should support substring matching on member paths."""
    rule_path = _make_test_path("semantic_left_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_AUTH_HEADER_CONTAINS
    title: "Bearer token assigned to any auth-like header path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    contains_any_of:
                      - "Authorization"
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'request.headers.Authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'request.headers.ContentType = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-left-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-left-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-left-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-left-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_ANY_AUTH_HEADER_CONTAINS" for f in positive_findings)
    assert not any(f.rule_id == "SEC_ANY_AUTH_HEADER_CONTAINS" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_regex_callee_match():
    """Semantic call rules should support regex matching on callee paths."""
    rule_path = _make_test_path("semantic_callee_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_HEADER_SETTER
    title: "Bearer token passed to any *.set auth-header setter"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_regex_any_of:
                    - "(?i)\\.set$"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = 'headersClient.set("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-callee-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-callee-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert any(f.rule_id == "SEC_ANY_HEADER_SETTER" for f in findings)


def test_yaml_semantic_call_expression_supports_contains_callee_match():
    """Semantic call rules should support substring matching on callee paths."""
    rule_path = _make_test_path("semantic_callee_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_HEADER_SETTER_CONTAINS
    title: "Bearer token passed to any *set* auth-header setter"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_contains_any_of:
                    - "set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'headersClient.set("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    negative_source = 'headersClient.append("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-callee-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-callee-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-callee-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-callee-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_ANY_HEADER_SETTER_CONTAINS" for f in positive_findings)
    assert not any(f.rule_id == "SEC_ANY_HEADER_SETTER_CONTAINS" for f in negative_findings)


def test_yaml_semantic_variable_declarator_supports_contains_identifier_match():
    """Semantic variable rules should support substring matching on identifier names."""
    rule_path = _make_test_path("semantic_identifier_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_TOKEN_IDENTIFIER_CONTAINS
    title: "Bearer token stored in token-like identifier"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_contains_any_of:
                    - "token"
              - init_contains_any_of:
                  any_of:
                    - "Bearer "
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const auth_token = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'const auth_value = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-id-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-id-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-id-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-id-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_TOKEN_IDENTIFIER_CONTAINS" for f in positive_findings)
    assert not any(f.rule_id == "SEC_TOKEN_IDENTIFIER_CONTAINS" for f in negative_findings)


def test_yaml_semantic_property_matches_helper_returned_nested_object_value():
    """Semantic property rules should resolve helper-returned nested object values."""
    rule_path = _make_test_path("semantic_property_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CONFIG_AUTH_PROPERTY
    title: "Bearer token stored in nested config property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "headers.Authorization"
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function buildAuth() {
      return "Bearer REALTOKENABCDEFGHIJKLMNOPQRSTUV123456";
    }
    const requestConfig = {
      headers: {
        Authorization: buildAuth()
      }
    };
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-property")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-property",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CONFIG_AUTH_PROPERTY")
    assert finding.extracted_value == "Bearer REALTOKENABCDEFGHIJKLMNOPQRSTUV123456"
    assert finding.metadata["property_path"] == "headers.Authorization"


def test_yaml_semantic_property_supports_regex_path_and_negative_guard():
    """Semantic property rules should support regex path matching plus negative guards on property values."""
    rule_path = _make_test_path("semantic_property_value_negative.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_AUTHZ_PROPERTY
    title: "Live bearer token stored in nested auth property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_regex_any_of:
                    - "(?i)headers\\.(authorization|x-auth-token)$"
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_value:
                  pattern: "(?i)demo|example|mock"
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const requestConfig = {
      headers: {
        "X-Auth-Token": "Bearer LIVETOKENABCDEFGHIJKLMNOPQRSTUV123456"
      }
    };
    """
    positive_result = JSParser().parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-property-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-property-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_source = """
    const requestConfig = {
      headers: {
        Authorization: "Bearer demo-token"
      }
    };
    """
    negative_result = JSParser().parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-property-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-property-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_ANY_AUTHZ_PROPERTY" for f in positive_findings)
    assert not any(f.rule_id == "SEC_ANY_AUTHZ_PROPERTY" for f in negative_findings)


def test_yaml_semantic_property_supports_contains_path_match():
    """Semantic property rules should support substring matching on property paths."""
    rule_path = _make_test_path("semantic_property_path_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ANY_AUTHZ_PROPERTY_CONTAINS
    title: "Live bearer token stored in auth-like property path"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_contains_any_of:
                    - "Authorization"
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const requestConfig = {
      headers: {
        Authorization: "Bearer LIVETOKENABCDEFGHIJKLMNOPQRSTUV123456"
      }
    };
    """
    negative_source = """
    const requestConfig = {
      headers: {
        ContentType: "Bearer LIVETOKENABCDEFGHIJKLMNOPQRSTUV123456"
      }
    };
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-property-path-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-property-path-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-property-path-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-property-path-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_ANY_AUTHZ_PROPERTY_CONTAINS" for f in positive_findings)
    assert not any(f.rule_id == "SEC_ANY_AUTHZ_PROPERTY_CONTAINS" for f in negative_findings)


def test_yaml_semantic_property_supports_exact_value_any_of_and_negative_guard():
    """Semantic property rules should support exact-value allowlists and denylists."""
    rule_path = _make_test_path("semantic_property_exact_value.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_CONFIG_MODE_EXACT
    title: "Exact config mode property"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "mode"
              - value_any_of:
                  any_of:
                    - "enabled"
                  capture_as: mode
              - not_value_any_of:
                  any_of:
                    - "demo"
                    - "disabled"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const config = { mode: "enabled" };
    """
    negative_source = """
    const config = { mode: "disabled" };
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-property-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-property-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-property-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-property-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_CONFIG_MODE_EXACT")
    assert finding.extracted_value == "enabled"
    assert not any(f.rule_id == "FLAG_CONFIG_MODE_EXACT" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_arg_any_of_and_negative_guard():
    """Semantic call rules should support exact argument allowlists and denylists."""
    rule_path = _make_test_path("semantic_call_exact_arg.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_FETCH_EXACT_ARG
    title: "Exact fetch endpoint argument"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - arg_any_of:
                  index: 0
                  any_of:
                    - "/api/users"
                    - "/api/profile"
                  capture_as: endpoint
              - not_arg_any_of:
                  index: 0
                  any_of:
                    - "/api/admin"
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    fetch("/api/users");
    """
    negative_source = """
    fetch("/api/admin");
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-arg-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-arg-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_FETCH_EXACT_ARG")
    assert finding.extracted_value == "/api/users"
    assert not any(f.rule_id == "ENDPOINT_FETCH_EXACT_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_member_path_arg_matching():
    """Semantic call rules should match static member-path arguments when no resolved string exists."""
    rule_path = _make_test_path("semantic_call_exact_member_path_arg.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_REQUEST_MEMBER_PATH_ARG
    title: "Exact request member-path argument"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - arg_any_of:
                  index: 0
                  any_of:
                    - "routes.users"
                    - "routes.profile"
                  capture_as: route_ref
              - not_arg_any_of:
                  index: 0
                  any_of:
                    - "assets.logo"
    extract:
      fields:
        route_ref: { from_capture: route_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'client.request(routes.users);'
    negative_source = 'client.request(assets.logo);'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-member-path-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-member-path-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_REQUEST_MEMBER_PATH_ARG")
    assert finding.extracted_value == "routes.users"
    assert not any(f.rule_id == "ENDPOINT_REQUEST_MEMBER_PATH_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_computed_member_path_arg_matching():
    """Semantic call rules should resolve constant-key computed member-path arguments."""
    rule_path = _make_test_path("semantic_call_exact_computed_member_path_arg.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_REQUEST_COMPUTED_MEMBER_PATH_ARG
    title: "Exact request computed member-path argument"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - arg_any_of:
                  index: 0
                  any_of:
                    - "ROUTES.users"
                  capture_as: route_ref
              - not_arg_any_of:
                  index: 0
                  any_of:
                    - "ASSETS.logo"
    extract:
      fields:
        route_ref: { from_capture: route_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
const key = "users";
client.request(ROUTES[key]);
""".strip()
    negative_source = """
const key = "logo";
client.request(ASSETS[key]);
""".strip()
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-computed-member-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-member-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-computed-member-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-member-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_REQUEST_COMPUTED_MEMBER_PATH_ARG")
    assert finding.extracted_value == "ROUTES.users"
    assert not any(f.rule_id == "ENDPOINT_REQUEST_COMPUTED_MEMBER_PATH_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_member_path_object_property_matching():
    """Semantic object-argument property rules should match static member-path property values."""
    rule_path = _make_test_path("semantic_call_exact_member_path_object_property.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_FETCH_MEMBER_PATH_PROPERTY
    title: "Member-path secret property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - object_arg_property_any_of:
                  index: 1
                  path: "headers.Authorization"
                  any_of:
                    - "tokens.auth"
                  capture_as: token_ref
              - not_object_arg_property_any_of:
                  index: 1
                  path: "headers.Authorization"
                  any_of:
                    - "assets.logo"
    extract:
      fields:
        token_ref: { from_capture: token_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'fetch("/api", { headers: { Authorization: tokens.auth } });'
    negative_source = 'fetch("/api", { headers: { Authorization: assets.logo } });'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-member-path-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-member-path-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SECRET_FETCH_MEMBER_PATH_PROPERTY")
    assert finding.extracted_value == "tokens.auth"
    assert not any(f.rule_id == "SECRET_FETCH_MEMBER_PATH_PROPERTY" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_computed_member_path_object_property_matching():
    """Semantic object-argument property rules should resolve constant-key computed member-path values."""
    rule_path = _make_test_path("semantic_call_exact_computed_member_path_object_property.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_FETCH_COMPUTED_MEMBER_PATH_PROPERTY
    title: "Computed member-path secret property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - object_arg_property_any_of:
                  index: 1
                  path: "headers.Authorization"
                  any_of:
                    - "TOKENS.auth"
                  capture_as: token_ref
              - not_object_arg_property_any_of:
                  index: 1
                  path: "headers.Authorization"
                  any_of:
                    - "ASSETS.logo"
    extract:
      fields:
        token_ref: { from_capture: token_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
const kind = "auth";
fetch("/api", { headers: { Authorization: TOKENS[kind] } });
""".strip()
    negative_source = """
const kind = "logo";
fetch("/api", { headers: { Authorization: ASSETS[kind] } });
""".strip()
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-computed-object-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-object-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-computed-object-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-object-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SECRET_FETCH_COMPUTED_MEMBER_PATH_PROPERTY")
    assert finding.extracted_value == "TOKENS.auth"
    assert not any(f.rule_id == "SECRET_FETCH_COMPUTED_MEMBER_PATH_PROPERTY" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_regex_member_path_arg_capture():
    """Semantic call rules should regex-match and capture static member-path arguments."""
    rule_path = _make_test_path("semantic_call_regex_member_path_arg.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_REQUEST_MEMBER_PATH_REGEX
    title: "Regex request member-path argument"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_arg:
                  index: 0
                  pattern: "^routes\\.[a-z]+$"
                  capture_as: route_ref
                  index_capture_as: arg_index
    extract:
      fields:
        route_ref: { from_capture: route_ref }
        matched_index: { from_capture: arg_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'client.request(routes.users);'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-member-path-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_REQUEST_MEMBER_PATH_REGEX")
    assert finding.extracted_value == "routes.users"
    assert finding.metadata["extracted_fields"]["matched_index"] == "0"


def test_yaml_semantic_call_expression_supports_regex_member_path_object_property_capture():
    """Semantic object-argument property rules should regex-match and capture static member-path values."""
    rule_path = _make_test_path("semantic_call_regex_member_path_object_property.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_FETCH_MEMBER_PATH_PROPERTY_REGEX
    title: "Regex member-path secret property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "^tokens\\.[a-z]+$"
                  capture_as: token_ref
                  path_capture_as: property_name
    extract:
      fields:
        token_ref: { from_capture: token_ref }
        property_name: { from_capture: property_name }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api", { headers: { Authorization: tokens.auth } });'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-member-path-object-regex")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-member-path-object-regex",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SECRET_FETCH_MEMBER_PATH_PROPERTY_REGEX")
    assert finding.extracted_value == "tokens.auth"
    assert finding.metadata["extracted_fields"]["property_name"] == "headers.Authorization"


def test_yaml_semantic_assignment_supports_exact_member_path_right_matching():
    """Semantic assignment rules should match static member-path right-hand values."""
    rule_path = _make_test_path("semantic_assignment_exact_member_path_right.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_ASSIGN_MEMBER_PATH_RIGHT
    title: "Assignment member-path secret value"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    any_of:
                      - "config.headers.Authorization"
              - right_any_of:
                  any_of:
                    - "tokens.auth"
                  capture_as: token_ref
              - not_right_any_of:
                  any_of:
                    - "assets.logo"
    extract:
      fields:
        token_ref: { from_capture: token_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.headers.Authorization = tokens.auth;'
    negative_source = 'config.headers.Authorization = assets.logo;'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-right-member-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-right-member-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-right-member-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-right-member-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SECRET_ASSIGN_MEMBER_PATH_RIGHT")
    assert finding.extracted_value == "tokens.auth"
    assert not any(f.rule_id == "SECRET_ASSIGN_MEMBER_PATH_RIGHT" for f in negative_findings)


def test_yaml_semantic_variable_declarator_supports_exact_member_path_init_matching():
    """Semantic variable rules should match static member-path initializers."""
    rule_path = _make_test_path("semantic_variable_exact_member_path_init.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_VAR_MEMBER_PATH_INIT
    title: "Variable member-path endpoint initializer"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_any_of:
                    - "currentRoute"
              - init_any_of:
                  any_of:
                    - "ROUTES.users"
                  capture_as: route_ref
              - not_init_any_of:
                  any_of:
                    - "ASSETS.logo"
    extract:
      fields:
        route_ref: { from_capture: route_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const currentRoute = ROUTES.users;'
    negative_source = 'const currentRoute = ASSETS.logo;'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-init-member-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-member-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-init-member-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-member-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_VAR_MEMBER_PATH_INIT")
    assert finding.extracted_value == "ROUTES.users"
    assert not any(f.rule_id == "ENDPOINT_VAR_MEMBER_PATH_INIT" for f in negative_findings)


def test_yaml_semantic_property_supports_regex_member_path_value_capture():
    """Semantic property rules should regex-match and capture static member-path values."""
    rule_path = _make_test_path("semantic_property_regex_member_path_value.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_PROPERTY_MEMBER_PATH_VALUE
    title: "Property member-path secret value"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "headers.Authorization"
              - regex_on_value:
                  pattern: "^tokens\\.[a-z]+$"
                  capture_as: token_ref
              - not_regex_on_value:
                  pattern: "^assets\\."
    extract:
      fields:
        token_ref: { from_capture: token_ref }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const config = { headers: { Authorization: tokens.auth } };'
    negative_source = 'const config = { headers: { Authorization: assets.logo } };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-value-member-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-value-member-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-value-member-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-value-member-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SECRET_PROPERTY_MEMBER_PATH_VALUE")
    assert finding.extracted_value == "tokens.auth"
    assert not any(f.rule_id == "SECRET_PROPERTY_MEMBER_PATH_VALUE" for f in negative_findings)


def test_yaml_semantic_property_supports_exact_computed_property_path_matching():
    """Semantic Property rules should resolve constant-key computed object-literal paths."""
    rule_path = _make_test_path("semantic_property_exact_computed_path.yml")
    rule_path.write_text(
        """
category: secret
rules:
  - id: SECRET_PROPERTY_COMPUTED_PATH
    title: "Computed property-path secret value"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "headers.Authorization"
                  property_path_capture_as: property_name
              - regex_on_value:
                  pattern: "^tokens\\.[a-z]+$"
                  capture_as: token_ref
    extract:
      fields:
        token_ref: { from_capture: token_ref }
        property_name: { from_capture: property_name }
""".strip(),
        encoding="utf-8",
    )

    source = """
const headerName = "Authorization";
const config = { headers: { [headerName]: tokens.auth } };
""".strip()
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-computed-property-path")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-computed-property-path",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SECRET_PROPERTY_COMPUTED_PATH")
    assert finding.extracted_value == "tokens.auth"
    assert finding.metadata["property_path"] == "headers.Authorization"
    assert finding.metadata["extracted_fields"]["property_name"] == "headers.Authorization"


def test_yaml_semantic_variable_declarator_supports_exact_init_any_of_and_negative_guard():
    """Semantic variable declarator rules should support exact initializer allowlists and denylists."""
    rule_path = _make_test_path("semantic_variable_exact_init.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_MODE_EXACT_INIT
    title: "Exact mode initializer"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_any_of:
                    - "mode"
              - init_any_of:
                  any_of:
                    - "production"
                  capture_as: mode
              - not_init_any_of:
                  any_of:
                    - "development"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const mode = "production";
    """
    negative_source = """
    const mode = "development";
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-init-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-init-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_MODE_EXACT_INIT")
    assert finding.extracted_value == "production"
    assert not any(f.rule_id == "FLAG_MODE_EXACT_INIT" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_exact_object_property_any_of_and_negative_guard():
    """Semantic object-argument rules should support exact property-value allowlists and denylists."""
    rule_path = _make_test_path("semantic_object_property_exact_value.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_CLIENT_MODE_EXACT
    title: "Exact client mode option"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_any_of:
                  index: 0
                  path_any_of:
                    - "mode"
                    - "config.mode"
                  any_of:
                    - "debug"
                  capture_as: mode
              - not_object_arg_property_any_of:
                  index: 0
                  path_any_of:
                    - "mode"
                    - "config.mode"
                  any_of:
                    - "demo"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestOptions() {
      return {
        config: {
          mode: "debug"
        }
      };
    }
    client.request(requestOptions());
    """
    negative_source = """
    client.request({
      mode: "demo"
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_CLIENT_MODE_EXACT")
    assert finding.extracted_value == "debug"
    assert not any(f.rule_id == "FLAG_CLIENT_MODE_EXACT" for f in negative_findings)


def test_yaml_semantic_assignment_supports_contains_right_any_of_and_negative_guard():
    """Semantic assignment rules should support substring allowlists and denylists."""
    rule_path = _make_test_path("semantic_assignment_contains_right.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_MODE_CONTAINS_RIGHT
    title: "Substring mode assignment"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    any_of:
                      - "config.mode"
              - right_contains_any_of:
                  any_of:
                    - "enabled"
                  capture_as: mode
              - not_right_contains_any_of:
                  any_of:
                    - "demo"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    config.mode = "enabled-preview";
    """
    negative_source = """
    config.mode = "enabled-demo";
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-right-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-right-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-right-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-right-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_MODE_CONTAINS_RIGHT")
    assert finding.extracted_value == "enabled-preview"
    assert not any(f.rule_id == "FLAG_MODE_CONTAINS_RIGHT" for f in negative_findings)


def test_yaml_semantic_variable_declarator_supports_contains_init_any_of_and_negative_guard():
    """Semantic variable rules should support substring initializer allowlists and denylists."""
    rule_path = _make_test_path("semantic_variable_contains_init.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_MODE_CONTAINS_INIT
    title: "Substring mode initializer"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_any_of:
                    - "mode"
              - init_contains_any_of:
                  any_of:
                    - "production"
                  capture_as: mode
              - not_init_contains_any_of:
                  any_of:
                    - "demo"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const mode = "production-east";
    """
    negative_source = """
    const mode = "production-demo";
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-init-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-init-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-init-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_MODE_CONTAINS_INIT")
    assert finding.extracted_value == "production-east"
    assert not any(f.rule_id == "FLAG_MODE_CONTAINS_INIT" for f in negative_findings)


def test_yaml_semantic_property_supports_contains_value_any_of_and_negative_guard():
    """Semantic property rules should support substring value allowlists and denylists."""
    rule_path = _make_test_path("semantic_property_contains_value.yml")
    rule_path.write_text(
        """
category: flags
rules:
  - id: FLAG_CONFIG_MODE_CONTAINS
    title: "Substring config mode property"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "mode"
              - value_contains_any_of:
                  any_of:
                    - "enabled"
                  capture_as: mode
              - not_value_contains_any_of:
                  any_of:
                    - "demo"
    extract:
      fields:
        mode: { from_capture: mode }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    const config = { mode: "enabled-preview" };
    """
    negative_source = """
    const config = { mode: "enabled-demo" };
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-value-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-value-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-value-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-value-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "FLAG_CONFIG_MODE_CONTAINS")
    assert finding.extracted_value == "enabled-preview"
    assert not any(f.rule_id == "FLAG_CONFIG_MODE_CONTAINS" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_contains_arg_any_of_and_negative_guard():
    """Semantic call rules should support substring argument allowlists and denylists."""
    rule_path = _make_test_path("semantic_call_contains_arg.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: ENDPOINT_FETCH_CONTAINS_ARG
    title: "Substring fetch endpoint argument"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - arg_contains_any_of:
                  index: 0
                  any_of:
                    - "/api/users"
                  capture_as: endpoint
              - not_arg_contains_any_of:
                  index: 0
                  any_of:
                    - "demo"
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    fetch("/api/users?view=full");
    """
    negative_source = """
    fetch("/api/users?mode=demo");
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-arg-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-arg-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-arg-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "ENDPOINT_FETCH_CONTAINS_ARG")
    assert finding.extracted_value == "/api/users?view=full"
    assert not any(f.rule_id == "ENDPOINT_FETCH_CONTAINS_ARG" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_contains_object_property_any_of_and_negative_guard():
    """Semantic object-argument rules should support substring property-value guards."""
    rule_path = _make_test_path("semantic_object_property_contains_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTHZ_CONTAINS
    title: "Substring authorization header option"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - object_arg_property_contains_any_of:
                  index: 0
                  path_any_of:
                    - "headers.Authorization"
                    - "config.headers.Authorization"
                  any_of:
                    - "Bearer "
                  capture_as: authorization
              - not_object_arg_property_contains_any_of:
                  index: 0
                  path_any_of:
                    - "headers.Authorization"
                    - "config.headers.Authorization"
                  any_of:
                    - "demo"
    extract:
      fields:
        authorization: { from_capture: authorization }
""".strip(),
        encoding="utf-8",
    )

    positive_source = """
    function requestOptions() {
      return {
        config: {
          headers: {
            Authorization: "Bearer prod-token"
          }
        }
      };
    }
    client.request(requestOptions());
    """
    negative_source = """
    client.request({
      headers: {
        Authorization: "Bearer demo-token"
      }
    });
    """
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-object-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-object-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_CLIENT_AUTHZ_CONTAINS")
    assert finding.extracted_value == "Bearer prod-token"
    assert not any(f.rule_id == "SEC_CLIENT_AUTHZ_CONTAINS" for f in negative_findings)


def test_yaml_semantic_call_expression_matches_destructured_helper_returned_argument():
    """Semantic call rules should resolve helper returns built through object destructuring."""
    rule_path = _make_test_path("semantic_destructured_helper_arg.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_DESTRUCTURED_HELPER
    title: "Fetch endpoint returned via destructured helper"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route() {
      const ROUTES = {
        users: "/api/users"
      };
      const { users: endpoint } = ROUTES;
      return endpoint;
    }
    fetch(route());
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-destructure-helper")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-destructure-helper",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_DESTRUCTURED_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_object_pattern_parameter_helper_return():
    """Semantic call rules should resolve helper params introduced via object destructuring."""
    rule_path = _make_test_path("semantic_object_pattern_param.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_PARAM_OBJECT_HELPER
    title: "Fetch endpoint returned from object-pattern helper param"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route({ users }) {
      return users;
    }
    fetch(route({ users: "/api/users" }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-pattern-param")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-pattern-param",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_PARAM_OBJECT_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_object_pattern_parameter_helper_return_from_spread_arg():
    """Semantic call rules should resolve object-pattern helper params from spread object arguments."""
    rule_path = _make_test_path("semantic_object_pattern_param_spread.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_PARAM_OBJECT_HELPER_SPREAD
    title: "Fetch endpoint returned from spread object-pattern helper param"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route({ users }) {
      return users;
    }
    const base = { users: "/docs/users" };
    fetch(route({ ...base, users: "/api/users" }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-pattern-param-spread")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-pattern-param-spread",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_PARAM_OBJECT_HELPER_SPREAD")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_object_property_helper_with_object_pattern_param():
    """Semantic object-property matchers should resolve config helpers with object-pattern params."""
    rule_path = _make_test_path("semantic_object_pattern_param_property.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_OBJECT_PARAM_HELPER
    title: "Bearer token passed via object-pattern config helper"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig({ token }) {
      return {
        headers: {
          Authorization: token
        }
      };
    }
    client.request(requestConfig({ token: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-pattern-param-prop")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-pattern-param-prop",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_OBJECT_PARAM_HELPER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"


def test_yaml_semantic_call_expression_matches_object_property_helper_with_object_pattern_param_from_spread_arg():
    """Semantic object-property matchers should resolve spread object-pattern helper params."""
    rule_path = _make_test_path("semantic_object_pattern_param_property_spread.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_OBJECT_PARAM_HELPER_SPREAD
    title: "Bearer token passed via spread object-pattern config helper"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig({ token }) {
      return {
        headers: {
          Authorization: token
        }
      };
    }
    const base = { token: "Token SHOULD_NOT_MATCH" };
    client.request(requestConfig({ ...base, token: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-pattern-param-prop-spread")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-pattern-param-prop-spread",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_OBJECT_PARAM_HELPER_SPREAD")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"


def test_yaml_semantic_call_expression_matches_nested_object_pattern_parameter_helper_return():
    """Semantic call rules should resolve nested object-pattern helper params."""
    rule_path = _make_test_path("semantic_nested_object_pattern_param.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_NESTED_PARAM_OBJECT_HELPER
    title: "Fetch endpoint returned from nested object-pattern helper param"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route({ api: { users } }) {
      return users;
    }
    fetch(route({ api: { users: "/api/users" } }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-nested-object-pattern-param")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-nested-object-pattern-param",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_NESTED_PARAM_OBJECT_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_object_property_helper_with_nested_object_pattern_param():
    """Semantic object-property matchers should resolve config helpers with nested object-pattern params."""
    rule_path = _make_test_path("semantic_nested_object_pattern_param_property.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_NESTED_OBJECT_PARAM_HELPER
    title: "Bearer token passed via nested object-pattern config helper"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig({ auth: { token } }) {
      return {
        headers: {
          Authorization: token
        }
      };
    }
    client.request(requestConfig({ auth: { token: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } }));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-nested-object-pattern-param-prop")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-nested-object-pattern-param-prop",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_NESTED_OBJECT_PARAM_HELPER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"


def test_yaml_semantic_call_expression_matches_object_pattern_parameter_default_helper_return():
    """Semantic call rules should resolve object-pattern helper defaults."""
    rule_path = _make_test_path("semantic_object_pattern_default_param.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_OBJECT_DEFAULT_PARAM_HELPER
    title: "Fetch endpoint returned from object-pattern helper default"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route({ users = "/api/users" }) {
      return users;
    }
    fetch(route({}));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-object-pattern-default-param")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-object-pattern-default-param",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_OBJECT_DEFAULT_PARAM_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_array_pattern_parameter_helper_return():
    """Semantic call rules should resolve array-pattern helper params."""
    rule_path = _make_test_path("semantic_array_pattern_param.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_ARRAY_PARAM_HELPER
    title: "Fetch endpoint returned from array-pattern helper param"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route([users]) {
      return users;
    }
    fetch(route(["/api/users"]));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-array-pattern-param")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-array-pattern-param",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_ARRAY_PARAM_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_array_pattern_parameter_default_helper_return():
    """Semantic call rules should resolve array-pattern helper defaults."""
    rule_path = _make_test_path("semantic_array_pattern_default_param.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: ENDPOINT_FETCH_ARRAY_DEFAULT_PARAM_HELPER
    title: "Fetch endpoint returned from array-pattern helper default"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/[a-z]+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function route([users = "/api/users"]) {
      return users;
    }
    fetch(route([]));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-array-pattern-default-param")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-array-pattern-default-param",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "ENDPOINT_FETCH_ARRAY_DEFAULT_PARAM_HELPER")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_call_expression_matches_object_property_helper_with_array_pattern_param():
    """Semantic object-property matchers should resolve config helpers with array-pattern params."""
    rule_path = _make_test_path("semantic_array_pattern_param_property.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_ARRAY_PARAM_HELPER
    title: "Bearer token passed via array-pattern config helper"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    source = """
    function requestConfig([token]) {
      return {
        headers: {
          Authorization: token
        }
      };
    }
    client.request(requestConfig(["Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"]));
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-array-pattern-param-prop")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-array-pattern-param-prop",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEC_CLIENT_AUTH_ARRAY_PARAM_HELPER")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"


def test_yaml_semantic_variable_declarator_supports_init_regex_and_negative_guard():
    """Semantic variable declarator rules should support init regexes plus negative guards."""
    rule_path = _make_test_path("semantic_variable_init.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_TOKEN_DECLARATOR
    title: "Bearer token variable declarator"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_regex_any_of:
                    - "(?i)token$"
              - regex_on_init:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_init:
                  pattern: "(?i)example|demo|sample"
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const authToken = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'const authToken = "Bearer example-token-1234567890";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-semantic-var-init-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-var-init-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-semantic-var-init-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-var-init-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    finding = next(f for f in positive_findings if f.rule_id == "SEC_TOKEN_DECLARATOR")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["declarator_name"] == "authToken"
    assert not any(f.rule_id == "SEC_TOKEN_DECLARATOR" for f in negative_findings)


def test_yaml_semantic_assignment_supports_negative_left_regex_guard():
    """Semantic assignment rules should support negative regex guards on left-hand paths."""
    rule_path = _make_test_path("semantic_assignment_not_left_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_ASSIGNMENT_NOT_DEBUG_AUTH
    title: "Bearer token assigned to auth path except debug auth"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: AssignmentExpression
                  left_matches:
                    regex_any_of:
                      - "(?i)auth"
                    not_regex_any_of:
                      - "(?i)debug"
              - regex_on_right:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.authHeader = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'config.debugAuth = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-assign-not-left-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-assign-not-left-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-assign-not-left-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-assign-not-left-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_ASSIGNMENT_NOT_DEBUG_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "SEC_ASSIGNMENT_NOT_DEBUG_AUTH" for f in negative_findings)


def test_yaml_semantic_call_expression_supports_negative_callee_contains_guard():
    """Semantic call rules should support negative substring guards on callees."""
    rule_path = _make_test_path("semantic_call_not_callee_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_CALL_NOT_MOCK_SETTER
    title: "Bearer token passed to non-mock setter"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_contains_any_of:
                    - "set"
                  not_callee_contains_any_of:
                    - "mock"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'headersClient.set("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    negative_source = 'headersmocksetter.set("Authorization", "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-call-not-callee-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-call-not-callee-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-call-not-callee-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-call-not-callee-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_CALL_NOT_MOCK_SETTER" for f in positive_findings)
    assert not any(f.rule_id == "SEC_CALL_NOT_MOCK_SETTER" for f in negative_findings)


def test_yaml_semantic_variable_declarator_supports_negative_identifier_contains_guard():
    """Semantic variable rules should support negative substring guards on identifier names."""
    rule_path = _make_test_path("semantic_variable_not_identifier_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_DECLARATOR_NOT_MOCK_TOKEN
    title: "Bearer token stored outside mock token identifiers"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: VariableDeclarator
                  id_name_contains_any_of:
                    - "token"
                  not_id_name_contains_any_of:
                    - "mock"
              - init_contains_any_of:
                  any_of:
                    - "Bearer "
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const auth_token = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'const mock_token = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-var-not-id-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-var-not-id-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-var-not-id-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-var-not-id-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_DECLARATOR_NOT_MOCK_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "SEC_DECLARATOR_NOT_MOCK_TOKEN" for f in negative_findings)


def test_yaml_semantic_property_supports_negative_property_path_regex_guard():
    """Semantic property rules should support negative regex guards on property paths."""
    rule_path = _make_test_path("semantic_property_not_path_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEC_PROPERTY_NOT_MOCK_AUTH
    title: "Bearer token stored in non-mock Authorization property"
    severity: high
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_contains_any_of:
                    - "Authorization"
                  not_property_path_regex_any_of:
                    - "(?i)^mock\\."
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const requestConfig = { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };'
    negative_source = 'const requestConfig = { mock: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-prop-not-path-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-prop-not-path-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-prop-not-path-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-prop-not-path-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "SEC_PROPERTY_NOT_MOCK_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "SEC_PROPERTY_NOT_MOCK_AUTH" for f in negative_findings)


def test_ast_pattern_call_expression_supports_negative_callee_regex_guard():
    """AST-pattern call rules should support negative regex guards on callees."""
    rule_path = _make_test_path("ast_pattern_not_callee_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_CALL_NOT_MOCK_FETCH
    title: "Non-mock fetch-like call"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_regex_any_of:
          - "(?i)fetch$"
        not_callee_regex_any_of:
          - "(?i)mock"
        args:
          - type: LiteralString
            regex: "^/api/"
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'client.fetch("/api/users");'
    negative_source = 'client.mockfetch("/api/users");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-call-not-callee-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-not-callee-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-call-not-callee-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-not-callee-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_CALL_NOT_MOCK_FETCH" for f in positive_findings)
    assert not any(f.rule_id == "AST_CALL_NOT_MOCK_FETCH" for f in negative_findings)


def test_ast_pattern_variable_declarator_supports_negative_identifier_regex_guard():
    """AST-pattern variable rules should support negative regex guards on identifier names."""
    rule_path = _make_test_path("ast_pattern_not_identifier_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_VAR_NOT_MOCK_TOKEN
    title: "Token-like variable excluding mock names"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_regex: "(?i)token$"
        not_id_name_regex: "(?i)^mock"
        init:
          type: LiteralString
          regex: "^Bearer\\s+"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const authToken = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'const mockToken = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-var-not-id-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-not-id-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-var-not-id-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-not-id-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_VAR_NOT_MOCK_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "AST_VAR_NOT_MOCK_TOKEN" for f in negative_findings)


def test_ast_pattern_assignment_expression_supports_negative_left_regex_guard():
    """AST-pattern assignment rules should support negative regex guards on left-hand paths."""
    rule_path = _make_test_path("ast_pattern_not_left_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_ASSIGN_NOT_DEBUG_AUTH
    title: "Auth assignment excluding debug path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: AssignmentExpression
        left_regex_any_of:
          - "(?i)auth"
        not_left_regex_any_of:
          - "(?i)debug"
        right:
          type: LiteralString
          regex: "^Bearer\\s+"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.authHeader = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'config.debugAuth = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-assign-not-left-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-not-left-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-assign-not-left-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-not-left-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_ASSIGN_NOT_DEBUG_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "AST_ASSIGN_NOT_DEBUG_AUTH" for f in negative_findings)


def test_ast_pattern_property_supports_negative_property_path_regex_guard():
    """AST-pattern property rules should support negative regex guards on property paths."""
    rule_path = _make_test_path("ast_pattern_not_property_path_regex.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_PROPERTY_NOT_MOCK_AUTH
    title: "Authorization property excluding mock path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: Property
        property_path_regex_any_of:
          - "(?i)(?:headers|mock)\\.Authorization$"
        not_property_path_regex_any_of:
          - "(?i)^mock\\."
        value:
          type: LiteralString
          regex: "^Bearer\\s+"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const requestConfig = { headers: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };'
    negative_source = 'const requestConfig = { mock: { Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" } };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-prop-not-path-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-not-path-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-prop-not-path-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-not-path-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_PROPERTY_NOT_MOCK_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "AST_PROPERTY_NOT_MOCK_AUTH" for f in negative_findings)


def test_ast_pattern_call_expression_supports_contains_and_negative_contains_guards():
    """AST-pattern call rules should support positive and negative substring matching."""
    rule_path = _make_test_path("ast_pattern_callee_contains.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: AST_CALL_CONTAINS_FETCH
    title: "Non-mock fetch-like call to API path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_contains_any_of:
          - "fetch"
        not_callee_contains_any_of:
          - "mock"
        args:
          - type: LiteralString
            contains_any_of:
              - "/api/"
            not_contains_any_of:
              - "/mock/"
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'client.fetch("/api/users");'
    negative_source = 'client.mockfetch("/api/users");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-call-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-call-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_CALL_CONTAINS_FETCH" for f in positive_findings)
    assert not any(f.rule_id == "AST_CALL_CONTAINS_FETCH" for f in negative_findings)


def test_ast_pattern_variable_declarator_supports_contains_and_negative_contains_guards():
    """AST-pattern variable rules should support positive and negative substring matching."""
    rule_path = _make_test_path("ast_pattern_identifier_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_VAR_CONTAINS_TOKEN
    title: "Token-like variable excluding mock names"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_contains_any_of:
          - "token"
        not_id_name_contains_any_of:
          - "mock"
        init:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const auth_token = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'const mock_token = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-var-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-var-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_VAR_CONTAINS_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "AST_VAR_CONTAINS_TOKEN" for f in negative_findings)


def test_ast_pattern_assignment_expression_supports_contains_and_negative_contains_guards():
    """AST-pattern assignment rules should support positive and negative substring matching."""
    rule_path = _make_test_path("ast_pattern_left_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_ASSIGN_CONTAINS_AUTH
    title: "Auth assignment excluding debug path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: AssignmentExpression
        left_contains_any_of:
          - "auth"
        not_left_contains_any_of:
          - "debug"
        right:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.authHeader = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    negative_source = 'config.debugauthHeader = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-assign-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-assign-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_ASSIGN_CONTAINS_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "AST_ASSIGN_CONTAINS_AUTH" for f in negative_findings)


def test_ast_pattern_property_supports_contains_and_negative_contains_guards():
    """AST-pattern property rules should support positive and negative substring matching."""
    rule_path = _make_test_path("ast_pattern_property_contains.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_PROPERTY_CONTAINS_AUTH
    title: "Auth property excluding mock path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: Property
        property_path_contains_any_of:
          - "auth_"
        not_property_path_contains_any_of:
          - "mock_"
        value:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const requestConfig = { auth_header: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" };'
    negative_source = 'const requestConfig = { mock_auth_header: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456" };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-prop-contains-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-contains-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-prop-contains-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-contains-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_PROPERTY_CONTAINS_AUTH" for f in positive_findings)
    assert not any(f.rule_id == "AST_PROPERTY_CONTAINS_AUTH" for f in negative_findings)


def test_ast_pattern_call_expression_supports_exact_and_negative_exact_value_guards():
    """AST-pattern call rules should support exact allow/deny value matching."""
    rule_path = _make_test_path("ast_pattern_call_exact_value.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: AST_CALL_EXACT_API
    title: "Exact API call excluding docs path"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            any_of:
              - "/api/users"
            not_any_of:
              - "/docs/users"
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'fetch("/api/users");'
    negative_source = 'fetch("/docs/users");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-call-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-call-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_CALL_EXACT_API" for f in positive_findings)
    assert not any(f.rule_id == "AST_CALL_EXACT_API" for f in negative_findings)


def test_ast_pattern_variable_declarator_supports_exact_and_negative_exact_init_guards():
    """AST-pattern variable rules should support exact allow/deny initializer matching."""
    rule_path = _make_test_path("ast_pattern_var_exact_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_VAR_EXACT_TOKEN
    title: "Exact token literal excluding placeholder"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_contains_any_of:
          - "token"
        init:
          type: LiteralString
          any_of:
            - "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP"
          not_any_of:
            - "Bearer placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const auth_token = "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP";'
    negative_source = 'const auth_token = "Bearer placeholder";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-var-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-var-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_VAR_EXACT_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "AST_VAR_EXACT_TOKEN" for f in negative_findings)


def test_ast_pattern_assignment_expression_supports_exact_and_negative_exact_right_guards():
    """AST-pattern assignment rules should support exact allow/deny right-value matching."""
    rule_path = _make_test_path("ast_pattern_assignment_exact_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_ASSIGN_EXACT_TOKEN
    title: "Exact auth assignment excluding placeholder"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: AssignmentExpression
        left_contains_any_of:
          - "auth"
        right:
          type: LiteralString
          any_of:
            - "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP"
          not_any_of:
            - "Bearer placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.authHeader = "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP";'
    negative_source = 'config.authHeader = "Bearer placeholder";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-assign-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-assign-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_ASSIGN_EXACT_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "AST_ASSIGN_EXACT_TOKEN" for f in negative_findings)


def test_ast_pattern_property_supports_exact_and_negative_exact_value_guards():
    """AST-pattern property rules should support exact allow/deny value matching."""
    rule_path = _make_test_path("ast_pattern_property_exact_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_PROPERTY_EXACT_TOKEN
    title: "Exact auth property excluding placeholder"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: Property
        property_path_contains_any_of:
          - "auth"
        value:
          type: LiteralString
          any_of:
            - "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP"
          not_any_of:
            - "Bearer placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const requestConfig = { auth_header: "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP" };'
    negative_source = 'const requestConfig = { auth_header: "Bearer placeholder" };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-prop-exact-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-exact-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-prop-exact-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-exact-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_PROPERTY_EXACT_TOKEN" for f in positive_findings)
    assert not any(f.rule_id == "AST_PROPERTY_EXACT_TOKEN" for f in negative_findings)


def test_ast_pattern_call_expression_supports_negative_regex_value_guard():
    """AST-pattern call rules should support negative regex guards on argument values."""
    rule_path = _make_test_path("ast_pattern_call_not_regex_value.yml")
    rule_path.write_text(
        """
category: endpoint
rules:
  - id: AST_CALL_NOT_REGEX_VALUE
    title: "API call excluding docs path by negative regex"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            contains_any_of:
              - "/users"
            not_regex: "^/docs/"
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'fetch("/api/users");'
    negative_source = 'fetch("/docs/users");'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-call-not-regex-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-not-regex-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-call-not-regex-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-not-regex-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_CALL_NOT_REGEX_VALUE" for f in positive_findings)
    assert not any(f.rule_id == "AST_CALL_NOT_REGEX_VALUE" for f in negative_findings)


def test_ast_pattern_variable_declarator_supports_negative_regex_init_guard():
    """AST-pattern variable rules should support negative regex guards on init values."""
    rule_path = _make_test_path("ast_pattern_var_not_regex_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_VAR_NOT_REGEX_INIT
    title: "Token-like variable excluding placeholder by negative regex"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_contains_any_of:
          - "token"
        init:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          not_regex: "(?i)placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const auth_token = "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP";'
    negative_source = 'const auth_token = "Bearer placeholder";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-var-not-regex-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-not-regex-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-var-not-regex-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-not-regex-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_VAR_NOT_REGEX_INIT" for f in positive_findings)
    assert not any(f.rule_id == "AST_VAR_NOT_REGEX_INIT" for f in negative_findings)


def test_ast_pattern_assignment_expression_supports_negative_regex_right_guard():
    """AST-pattern assignment rules should support negative regex guards on right-hand values."""
    rule_path = _make_test_path("ast_pattern_assignment_not_regex_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_ASSIGN_NOT_REGEX_RIGHT
    title: "Auth assignment excluding placeholder by negative regex"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: AssignmentExpression
        left_contains_any_of:
          - "auth"
        right:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          not_regex: "(?i)placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'config.authHeader = "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP";'
    negative_source = 'config.authHeader = "Bearer placeholder";'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-assign-not-regex-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-not-regex-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-assign-not-regex-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-not-regex-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_ASSIGN_NOT_REGEX_RIGHT" for f in positive_findings)
    assert not any(f.rule_id == "AST_ASSIGN_NOT_REGEX_RIGHT" for f in negative_findings)


def test_ast_pattern_property_supports_negative_regex_value_guard():
    """AST-pattern property rules should support negative regex guards on property values."""
    rule_path = _make_test_path("ast_pattern_property_not_regex_value.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_PROPERTY_NOT_REGEX_VALUE
    title: "Auth property excluding placeholder by negative regex"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: Property
        property_path_contains_any_of:
          - "auth"
        value:
          type: LiteralString
          contains_any_of:
            - "Bearer "
          not_regex: "(?i)placeholder"
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
""".strip(),
        encoding="utf-8",
    )

    positive_source = 'const requestConfig = { auth_header: "Bearer REALTOKEN1234567890ABCDEFGHIJKLMNOP" };'
    negative_source = 'const requestConfig = { auth_header: "Bearer placeholder" };'
    parser = JSParser()

    positive_result = parser.parse(positive_source)
    assert positive_result.success is True
    assert positive_result.ast is not None
    positive_ir = IRBuilder().build(positive_result.ast, "file:///bundle.js", "hash-ast-prop-not-regex-positive")
    positive_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-not-regex-positive",
        source_content=positive_source,
        is_first_party=True,
    )

    negative_result = parser.parse(negative_source)
    assert negative_result.success is True
    assert negative_result.ast is not None
    negative_ir = IRBuilder().build(negative_result.ast, "file:///bundle.js", "hash-ast-prop-not-regex-negative")
    negative_context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-not-regex-negative",
        source_content=negative_source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()

    positive_findings = engine.analyze(positive_ir, positive_context)
    negative_findings = engine.analyze(negative_ir, negative_context)

    assert any(f.rule_id == "AST_PROPERTY_NOT_REGEX_VALUE" for f in positive_findings)
    assert not any(f.rule_id == "AST_PROPERTY_NOT_REGEX_VALUE" for f in negative_findings)


def test_ast_pattern_call_expression_can_capture_callee_path():
    """AST-pattern call rules should capture matched callee paths for extraction."""
    rule_path = _make_test_path("ast_pattern_call_callee_capture.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: AST_CALL_CALLEE_CAPTURE
    title: "Call expression callee capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_contains_any_of:
          - "request"
        callee_capture_as: matched_callee
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        callee_name: { from_capture: matched_callee }
""".strip(),
        encoding="utf-8",
    )

    source = 'client.request("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-call-callee-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-callee-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_CALL_CALLEE_CAPTURE")
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["callee_name"] == "client.request"


def test_ast_pattern_variable_declarator_can_capture_identifier_name():
    """AST-pattern variable rules should capture matched declarator names for extraction."""
    rule_path = _make_test_path("ast_pattern_var_identifier_capture.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_VAR_IDENTIFIER_CAPTURE
    title: "Variable declarator identifier capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: VariableDeclarator
        id_name_regex: "(?i)token$"
        id_name_capture_as: declarator_name
        init:
          type: LiteralString
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        declarator: { from_capture: declarator_name }
""".strip(),
        encoding="utf-8",
    )

    source = 'const authToken = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-var-id-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-var-id-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_VAR_IDENTIFIER_CAPTURE")
    assert finding.extracted_value == "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    assert finding.metadata["extracted_fields"]["declarator"] == "authToken"


def test_ast_pattern_assignment_can_capture_left_path():
    """AST-pattern assignment rules should capture matched left-hand paths for extraction."""
    rule_path = _make_test_path("ast_pattern_assignment_left_capture.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_ASSIGN_LEFT_CAPTURE
    title: "Assignment left-path capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: AssignmentExpression
        left_contains_any_of:
          - "auth"
        left_capture_as: target_path
        right:
          type: LiteralString
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        target: { from_capture: target_path }
""".strip(),
        encoding="utf-8",
    )

    source = 'config.headers.authHeader = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456";'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-assign-left-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-assign-left-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_ASSIGN_LEFT_CAPTURE")
    assert finding.metadata["extracted_fields"]["target"] == "config.headers.authHeader"


def test_ast_pattern_property_can_capture_property_path():
    """AST-pattern property rules should capture matched nested property paths for extraction."""
    rule_path = _make_test_path("ast_pattern_property_path_capture.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: AST_PROPERTY_PATH_CAPTURE
    title: "Property path capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: Property
        property_path_contains_any_of:
          - "Authorization"
        property_path_capture_as: matched_path
        value:
          type: LiteralString
          capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        property_name: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    const requestConfig = {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    };
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-prop-path-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-prop-path-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_PROPERTY_PATH_CAPTURE")
    assert finding.metadata["extracted_fields"]["property_name"] == "headers.Authorization"


def test_yaml_semantic_call_expression_ast_can_capture_callee_path():
    """Semantic AST clauses should capture matched callees for extraction."""
    rule_path = _make_test_path("semantic_call_ast_callee_capture.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_CALL_AST_CALLEE_CAPTURE
    title: "Semantic AST callee capture"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_contains_any_of:
                    - "request"
                  callee_capture_as: matched_callee
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/.+$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        callee_name: { from_capture: matched_callee }
""".strip(),
        encoding="utf-8",
    )

    source = 'client.request("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-sem-call-callee-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-sem-call-callee-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_CALL_AST_CALLEE_CAPTURE")
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["callee_name"] == "client.request"


def test_yaml_semantic_property_ast_can_capture_property_path():
    """Semantic AST clauses should capture matched property paths for extraction."""
    rule_path = _make_test_path("semantic_property_ast_path_capture.yml")
    rule_path.write_text(
        """
category: secrets
rules:
  - id: SEM_PROPERTY_AST_PATH_CAPTURE
    title: "Semantic AST property-path capture"
    severity: medium
    confidence: high
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_contains_any_of:
                    - "Authorization"
                  property_path_capture_as: matched_path
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token }
        property_name: { from_capture: matched_path }
""".strip(),
        encoding="utf-8",
    )

    source = """
    const requestConfig = {
      headers: {
        Authorization: "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
      }
    };
    """
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-sem-prop-path-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-sem-prop-path-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_PROPERTY_AST_PATH_CAPTURE")
    assert finding.metadata["extracted_fields"]["property_name"] == "headers.Authorization"


def test_ast_pattern_call_expression_can_capture_matched_arg_index():
    """AST-pattern call rules should capture matched positional argument indexes."""
    rule_path = _make_test_path("ast_pattern_call_arg_index_capture.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: AST_CALL_ARG_INDEX_CAPTURE
    title: "AST call argument index capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            index_capture_as: endpoint_index
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        arg_index: { from_capture: endpoint_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-call-arg-index-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-arg-index-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_CALL_ARG_INDEX_CAPTURE")
    assert finding.metadata["extracted_fields"]["arg_index"] == "0"


def test_ast_pattern_new_expression_any_arg_can_capture_matched_arg_index():
    """AST-pattern constructor rules should capture indexes even for `Any` arg matchers."""
    rule_path = _make_test_path("ast_pattern_new_any_arg_index_capture.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: AST_NEW_ANY_ARG_INDEX_CAPTURE
    title: "AST constructor any-arg index capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: NewExpression
        callee_any_of:
          - "Request"
        args:
          - type: Any
          - type: Any
            index_capture_as: options_index
    extract:
      fields:
        endpoint: { static: "constructor_options_seen" }
        arg_index: { from_capture: options_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'new Request("/api/users", { method: "POST" });'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-new-any-arg-index-capture")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-new-any-arg-index-capture",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_NEW_ANY_ARG_INDEX_CAPTURE")
    assert finding.metadata["extracted_fields"]["arg_index"] == "1"


def test_ast_pattern_call_expression_regex_arg_supports_index_any_of():
    """AST-pattern call rules should match across multiple candidate arg indices."""
    rule_path = _make_test_path("ast_pattern_call_arg_index_any_of.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: AST_CALL_ARG_INDEX_ANY_OF
    title: "AST call argument multi-index match"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "request"
        args:
          - type: LiteralString
            any_of:
              - "POST"
          - type: LiteralString
            index_any_of:
              - 0
              - 1
            regex: "^/api/.*$"
            index_capture_as: endpoint_index
            capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
        arg_index: { from_capture: endpoint_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'request("POST", "/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-call-arg-index-any-of")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-call-arg-index-any-of",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_CALL_ARG_INDEX_ANY_OF")
    assert finding.extracted_value == "/api/users"
    assert finding.metadata["extracted_fields"]["arg_index"] == "1"


def test_ast_pattern_new_expression_any_arg_supports_index_any_of():
    """AST-pattern constructor rules should resolve the first matching unused candidate index."""
    rule_path = _make_test_path("ast_pattern_new_any_arg_index_any_of.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: AST_NEW_ANY_ARG_INDEX_ANY_OF
    title: "AST constructor multi-index any-arg capture"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: NewExpression
        callee_any_of:
          - "Request"
        args:
          - type: Any
          - type: Any
            index_any_of:
              - 0
              - 1
            index_capture_as: options_index
    extract:
      fields:
        endpoint: { static: "constructor_options_seen" }
        arg_index: { from_capture: options_index }
""".strip(),
        encoding="utf-8",
    )

    source = 'new Request("/api/users", { method: "POST" });'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-ast-new-any-arg-index-any-of")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-ast-new-any-arg-index-any-of",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "AST_NEW_ANY_ARG_INDEX_ANY_OF")
    assert finding.metadata["extracted_fields"]["arg_index"] == "1"


def test_yaml_semantic_call_expression_supports_logic_all_shorthand():
    """Semantic rules should accept top-level logic.all as a single AND clause."""
    rule_path = _make_test_path("semantic_logic_all.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_ALL
    title: "Semantic logic.all shorthand"
    matcher:
      type: semantic
      logic:
        all:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
          - regex_on_arg:
              index: 0
              pattern: "^/api/.*$"
              capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-all")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-all",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_LOGIC_ALL")
    assert finding.extracted_value == "/api/users"
    assert finding.evidence.ast_node_type == "CallExpression"


def test_yaml_semantic_logic_all_requires_every_condition():
    """Semantic logic.all should fail when any condition in the shorthand clause does not match."""
    rule_path = _make_test_path("semantic_logic_all_negative.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_ALL_NEGATIVE
    title: "Semantic logic.all negative"
    matcher:
      type: semantic
      logic:
        all:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
          - regex_on_arg:
              index: 0
              pattern: "^/api/.*$"
              capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/docs/getting-started");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-all-negative")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-all-negative",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert not any(f.rule_id == "SEM_LOGIC_ALL_NEGATIVE" for f in findings)


def test_yaml_semantic_call_expression_supports_logic_any_direct_clause_shorthand():
    """Semantic rules should accept direct logic.any clause objects without an explicit and wrapper."""
    rule_path = _make_test_path("semantic_logic_any_direct_clause.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_ANY_DIRECT
    title: "Semantic logic.any direct clause"
    matcher:
      type: semantic
      logic:
        any:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
            regex_on_arg:
              index: 0
              pattern: "^/api/.*$"
              capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/direct-clause");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-any-direct")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-any-direct",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_LOGIC_ANY_DIRECT")
    assert finding.extracted_value == "/api/direct-clause"
    assert finding.evidence.ast_node_type == "CallExpression"


def test_yaml_semantic_call_expression_supports_logic_none_shorthand():
    """Semantic rules should accept top-level logic.none as a negative shorthand."""
    rule_path = _make_test_path("semantic_logic_none.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_NONE
    title: "Semantic logic.none shorthand"
    matcher:
      type: semantic
      logic:
        all:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
          - arg_contains_any_of:
              index: 0
              any_of:
                - "/api/"
              capture_as: endpoint
        none:
          - arg_contains_any_of:
              index: 0
              any_of:
                - "/docs/"
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-none")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-none",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_LOGIC_NONE")
    assert finding.extracted_value == "/api/users"


def test_yaml_semantic_logic_all_supports_top_level_clause_object():
    """Semantic logic.all should accept a full clause object, not only flat condition lists."""
    rule_path = _make_test_path("semantic_logic_all_clause_object.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_ALL_CLAUSE
    title: "Semantic logic.all clause object"
    matcher:
      type: semantic
      logic:
        any:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
        all:
          or:
            - arg_contains_any_of:
                index: 0
                any_of:
                  - "/api/users"
                capture_as: endpoint
            - arg_contains_any_of:
                index: 0
                any_of:
                  - "/api/admin"
                capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/admin");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-all-clause-object")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-all-clause-object",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_LOGIC_ALL_CLAUSE")
    assert finding.extracted_value == "/api/admin"


def test_yaml_semantic_logic_none_supports_top_level_clause_object():
    """Semantic logic.none should accept a full clause object and block matching when it resolves."""
    rule_path = _make_test_path("semantic_logic_none_clause_object.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_LOGIC_NONE_CLAUSE
    title: "Semantic logic.none clause object"
    matcher:
      type: semantic
      logic:
        any:
          - ast:
              kind: CallExpression
              callee_any_of:
                - "fetch"
            arg_contains_any_of:
              index: 0
              any_of:
                - "/api/"
              capture_as: endpoint
        none:
          or:
            - arg_contains_any_of:
                index: 0
                any_of:
                  - "/docs/"
            - arg_contains_any_of:
                index: 0
                any_of:
                  - "/admin/"
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/docs/guide");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-logic-none-clause-object")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-logic-none-clause-object",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    assert not any(f.rule_id == "SEM_LOGIC_NONE_CLAUSE" for f in findings)


def test_yaml_semantic_call_expression_supports_clause_level_or():
    """Semantic clauses should allow `or:` sibling conditions inside one clause."""
    rule_path = _make_test_path("semantic_clause_or.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_CLAUSE_OR
    title: "Semantic clause or"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
            or:
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/users$"
                  capture_as: endpoint
              - regex_on_arg:
                  index: 0
                  pattern: "^/api/admin$"
                  capture_as: endpoint
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/admin");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-clause-or")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-clause-or",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_CLAUSE_OR")
    assert finding.extracted_value == "/api/admin"


def test_yaml_semantic_call_expression_supports_clause_level_not():
    """Semantic clauses should allow `not:` sibling conditions inside one clause."""
    rule_path = _make_test_path("semantic_clause_not.yml")
    rule_path.write_text(
        """
category: endpoints
rules:
  - id: SEM_CLAUSE_NOT
    title: "Semantic clause not"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - arg_contains_any_of:
                  index: 0
                  any_of:
                    - "/api/"
                  capture_as: endpoint
            not:
              - arg_contains_any_of:
                  index: 0
                  any_of:
                    - "/docs/"
    extract:
      fields:
        endpoint: { from_capture: endpoint }
""".strip(),
        encoding="utf-8",
    )

    source = 'fetch("/api/users");'
    parser = JSParser()
    parse_result = parser.parse(source)
    assert parse_result.success is True
    assert parse_result.ast is not None

    ir = IRBuilder().build(parse_result.ast, "file:///bundle.js", "hash-semantic-clause-not")
    context = AnalysisContext(
        file_url="file:///bundle.js",
        file_hash="hash-semantic-clause-not",
        source_content=source,
        is_first_party=True,
    )

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    findings = engine.analyze(ir, context)

    finding = next(f for f in findings if f.rule_id == "SEM_CLAUSE_NOT")
    assert finding.extracted_value == "/api/users"

