"""Tests for secret detector.

All token/key strings in this module are intentionally fake sample values for
regression testing. They are not live credentials.
"""

import pytest

from tests.fixtures.fake_secrets import (
    FAKE_AWS_ACCESS_KEY,
    FAKE_GITHUB_PAT,
    FAKE_MAILGUN_API_KEY,
    FAKE_MAILGUN_PRIVATE_KEY,
    FAKE_STRIPE_LIVE,
)
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.secrets import SecretDetector
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Severity, Confidence


class TestSecretDetector:
    """Tests for SecretDetector."""

    @pytest.fixture
    def detector(self):
        return SecretDetector()

    @pytest.fixture
    def context(self):
        return AnalysisContext(
            file_url="https://example.com/app.js",
            file_hash="abc123",
            source_content="",
        )

    def _analyze(self, source: str, detector: SecretDetector, context: AnalysisContext):
        """Helper to analyze source code."""
        result = parse_js(source)
        assert result.success

        ir = build_ir(result.ast, context.file_url, context.file_hash)
        context.source_content = source

        return list(detector.match(ir, context))

    def _engine_analyze(self, source: str, context: AnalysisContext):
        """Helper to run the full rule engine with context filtering."""
        result = parse_js(source)
        assert result.success

        ir = build_ir(result.ast, context.file_url, context.file_hash)
        context.source_content = source

        engine = RuleEngine()
        engine.register_defaults()
        return engine.analyze(ir, context)

    def test_detect_aws_key(self, detector, context):
        """Test detection of AWS access key."""
        source = '''
        const AWS_KEY = "__AWS_ACCESS_KEY__";
        '''.replace("__AWS_ACCESS_KEY__", FAKE_AWS_ACCESS_KEY)
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        aws_finding = next(
            (f for f in findings if "aws" in f.value_type.lower()),
            None
        )
        assert aws_finding is not None
        assert aws_finding.severity == Severity.CRITICAL

    def test_detect_jwt(self, detector, context):
        """Test detection of JWT token."""
        source = '''
        const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        jwt_finding = next(
            (f for f in findings if "jwt" in f.value_type.lower()),
            None
        )
        assert jwt_finding is not None

    def test_detect_stripe_key(self, detector, context):
        """Test detection of Stripe secret key."""
        source = '''
        const stripeKey = "__STRIPE_LIVE__";
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE)
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        stripe_finding = next(
            (f for f in findings if "stripe" in f.value_type.lower()),
            None
        )
        assert stripe_finding is not None
        assert stripe_finding.severity == Severity.CRITICAL

    def test_exclude_placeholder(self, detector, context):
        """Test exclusion of placeholder values."""
        source = '''
        const key = "your-api-key-here";
        const test = "test_key_placeholder";
        '''
        findings = self._analyze(source, detector, context)

        # Should not detect placeholders
        assert all("placeholder" not in f.extracted_value.lower() for f in findings)

    def test_detect_database_url(self, detector, context):
        """Test detection of database connection string."""
        source = '''
        const dbUrl = "mongodb://user:password@localhost:27017/mydb";
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        db_finding = next(
            (f for f in findings if "mongodb" in f.value_type.lower() or "database" in f.value_type.lower()),
            None
        )
        assert db_finding is not None
        assert db_finding.severity == Severity.CRITICAL

    def test_detect_aws_secret_key_extracts_value_only(self, detector, context):
        """AWS secret extraction should not include assignment context or quotes."""
        source = '''
        const config = "aws_secret_key = \\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\"";
        '''
        findings = self._analyze(source, detector, context)

        aws_secret = next((f for f in findings if f.value_type == "aws_secret_key"), None)
        assert aws_secret is not None
        assert aws_secret.extracted_value == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    def test_mailgun_api_key_requires_boundaries(self, detector, context):
        """Mailgun API keys should not match inside larger identifiers."""
        source = f'''
        const embedded = "prefix{FAKE_MAILGUN_API_KEY}suffix";
        const exact = "{FAKE_MAILGUN_API_KEY}";
        '''
        findings = self._analyze(source, detector, context)

        assert any(f.value_type == "mailgun_api_key" and f.extracted_value == FAKE_MAILGUN_API_KEY for f in findings)
        assert not any("prefixkey-" in f.extracted_value for f in findings)

    def test_mailgun_private_key_requires_terminal_boundary(self, detector, context):
        """Mailgun private key patterns should not match longer hex-dash identifiers."""
        source = f'''
        const embedded = "{FAKE_MAILGUN_PRIVATE_KEY}-z";
        const exact = "{FAKE_MAILGUN_PRIVATE_KEY}";
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.value_type == "mailgun_private_key"
            and f.extracted_value == FAKE_MAILGUN_PRIVATE_KEY
            for f in findings
        )
        assert not any(
            f.value_type == "mailgun_private_key" and f.extracted_value.endswith("-z")
            for f in findings
        )

    def test_entropy_detection(self, detector, context):
        """Test high-entropy string detection."""
        source = '''
        const secret = "aB3$kL9mN2pQ5rT8uW1xY4zA7cD0eF6gH";
        '''
        findings = self._analyze(source, detector, context)

        # High entropy string should be flagged
        assert len(findings) >= 1

    def test_context_filter_excludes_non_secret_version_hash(self, context):
        """Version/hash values should not survive the engine context filter."""
        source = '''
        const version = "0123456789abcdef0123456789abcdef";
        const assetHash = "fedcba9876543210fedcba9876543210";
        '''
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_keeps_real_secret(self, context):
        """Real secrets should still survive context filtering."""
        source = '''
        const apiKey = "__STRIPE_LIVE__";
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE)
        findings = self._engine_analyze(source, context)

        assert any(f.rule_id == "secret-detector" for f in findings)

    def test_context_filter_excludes_comment_only_secret_like_value(self, context):
        """Secret-like strings that appear only in comments should be dropped."""
        source = '''
        // authorization = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
        '''
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_example_variable_secret_like_value(self, context):
        """Example/demo variable names should suppress otherwise secret-looking literals."""
        source = '''
        const exampleToken = "__STRIPE_LIVE__";
        const demoSecret = "__GITHUB_PAT__";
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE).replace("__GITHUB_PAT__", FAKE_GITHUB_PAT)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_mock_object_key_secret_like_value(self, context):
        """Mock/sample object keys should suppress otherwise secret-looking literals."""
        source = '''
        const fixtures = {
          mockApiKey: "__STRIPE_LIVE__",
          sampleToken: "__GITHUB_PAT__",
        };
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE).replace("__GITHUB_PAT__", FAKE_GITHUB_PAT)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_example_console_log_secret_like_value(self, context):
        """Example/test logging strings should not survive context filtering."""
        source = '''
        console.log("example __STRIPE_LIVE__");
        console.info("test __GITHUB_PAT__");
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE).replace("__GITHUB_PAT__", FAKE_GITHUB_PAT)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_block_comment_secret_like_value(self, context):
        """Secret-like values inside block comments should not survive context filtering."""
        source = '''
        /*
         * Example token for docs:
         * __STRIPE_LIVE__
         */
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_readme_docs_variable_secret_like_value(self, context):
        """Readme/docs/snippet variable names should suppress otherwise secret-looking literals."""
        source = '''
        const readmeSnippet = "__STRIPE_LIVE__";
        const docsTokenGuide = "__GITHUB_PAT__";
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE).replace("__GITHUB_PAT__", FAKE_GITHUB_PAT)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_context_filter_excludes_docs_object_key_secret_like_value(self, context):
        """Docs/snippet object keys should suppress otherwise secret-looking literals."""
        source = '''
        const docsConfig = {
          snippetToken: "__STRIPE_LIVE__",
          tutorialSecret: "__GITHUB_PAT__",
        };
        '''.replace("__STRIPE_LIVE__", FAKE_STRIPE_LIVE).replace("__GITHUB_PAT__", FAKE_GITHUB_PAT)
        findings = self._engine_analyze(source, context)

        assert not any(f.category.value == "secret" for f in findings)

    def test_detect_session_token_with_moderate_severity_and_confidence(self, detector, context):
        """Session-like assignments should be detected without escalating to high severity."""
        source = '''
        const session_token = "abcdefghijklmnopqrstuvwxyz123456";
        '''
        findings = self._analyze(source, detector, context)

        session_finding = next((f for f in findings if f.value_type == "session_token"), None)
        assert session_finding is not None
        assert session_finding.severity == Severity.MEDIUM
        assert session_finding.confidence == Confidence.MEDIUM
        assert session_finding.extracted_value == "abcdefghijklmnopqrstuvwxyz123456"

    def test_detect_auth_header_preserves_matched_text_metadata(self, detector, context):
        """Captured auth values should retain the original matched text for reporting."""
        source = '''
        const authorization = "Bearer abcdefghijklmnopqrstuvwxyz123456";
        '''
        findings = self._analyze(source, detector, context)

        auth_finding = next((f for f in findings if f.value_type == "auth_header"), None)
        assert auth_finding is not None
        assert auth_finding.severity == Severity.MEDIUM
        assert auth_finding.confidence == Confidence.MEDIUM
        assert auth_finding.metadata["matched_text"] == 'authorization = "Bearer abcdefghijklmnopqrstuvwxyz123456"'
        assert auth_finding.metadata["match_uses_capture_group"] is True

    def test_detect_session_jwt_downgrades_to_session_context(self, detector, context):
        """JWTs stored in explicit session context should not be escalated as generic high-risk auth tokens."""
        source = '''
        const sessionToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        '''
        findings = self._analyze(source, detector, context)

        session_finding = next((f for f in findings if f.extracted_value.startswith("eyJ")), None)
        assert session_finding is not None
        assert session_finding.value_type == "session_token"
        assert session_finding.severity == Severity.MEDIUM
        assert session_finding.confidence == Confidence.MEDIUM
        assert session_finding.metadata["matched_pattern_type"] == "jwt_token"
        assert session_finding.metadata["contextual_type_override"] == "session_token"

