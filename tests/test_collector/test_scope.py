"""Tests for scope policy."""

import time

import pytest

from bundleInspector.collector.scope import ScopePolicy, normalize_url, is_js_url
from bundleInspector.config import ScopeConfig, ThirdPartyPolicy


class TestScopePolicy:
    """Tests for ScopePolicy."""

    def test_allowed_domain_match(self):
        """Test matching allowed domains."""
        config = ScopeConfig(
            allowed_domains=["example.com", "*.example.com"],
        )
        policy = ScopePolicy(config)

        assert policy.is_allowed("https://example.com/page")
        assert policy.is_allowed("https://sub.example.com/page")
        assert policy.is_allowed("https://deep.sub.example.com/page")

    def test_denied_domain_blocks(self):
        """Test denied domains are blocked."""
        config = ScopeConfig(
            allowed_domains=["*.example.com"],
            denied_domains=["blocked.example.com"],
        )
        policy = ScopePolicy(config)

        assert policy.is_allowed("https://ok.example.com/page")
        assert not policy.is_allowed("https://blocked.example.com/page")

    def test_denied_path_blocks(self):
        """Test denied paths are blocked."""
        config = ScopeConfig(
            denied_paths=["/admin", "/internal"],
        )
        policy = ScopePolicy(config)

        assert policy.is_allowed("https://example.com/page")
        assert not policy.is_allowed("https://example.com/admin/users")
        assert not policy.is_allowed("https://example.com/internal/api")

    def test_third_party_policy_skip(self):
        """Test third-party skip policy."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            third_party_policy=ThirdPartyPolicy.SKIP,
        )
        policy = ScopePolicy(config)

        assert policy.is_allowed("https://example.com/app.js")
        assert not policy.is_allowed("https://other.com/lib.js")

    def test_first_party_detection(self):
        """Test first-party detection."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
        )
        policy = ScopePolicy(config)

        assert policy.is_first_party("https://example.com/app.js")
        assert not policy.is_first_party("https://cdn.cloudflare.com/lib.js")

    def test_cdn_detection(self):
        """Test CDN detection."""
        config = ScopeConfig()
        policy = ScopePolicy(config)

        # Patterns are *.domain format, so need subdomain prefix
        assert policy._is_cdn("npm.cdn.jsdelivr.net")  # matches *.cdn.jsdelivr.net
        assert policy._is_cdn("cdn.cloudflare.com")    # matches *.cloudflare.com
        assert policy._is_cdn("fonts.googleapis.com")  # matches *.googleapis.com
        assert not policy._is_cdn("example.com")


class TestScopePolicyReDoSPrevention:
    """Tests for ReDoS prevention in scope policy."""

    def test_pattern_length_limit(self):
        """Test that overly long patterns are rejected."""
        long_pattern = "a" * 300  # Exceeds MAX_PATTERN_LENGTH
        config = ScopeConfig(
            allowed_domains=[long_pattern],
        )
        policy = ScopePolicy(config)

        # Pattern should be ignored
        assert len(policy._compiled_allowed) == 0

    def test_wildcard_count_limit(self):
        """Test that patterns with too many wildcards are rejected."""
        many_wildcards = "*.*.*.*.*.*"  # 6 wildcards
        config = ScopeConfig(
            allowed_domains=[many_wildcards],
        )
        policy = ScopePolicy(config)

        # Pattern should be ignored
        assert len(policy._compiled_allowed) == 0

    def test_pattern_count_limit(self):
        """Test that excess patterns are truncated."""
        patterns = [f"domain{i}.com" for i in range(150)]
        config = ScopeConfig(
            allowed_domains=patterns,
        )
        policy = ScopePolicy(config)

        # Should be limited to MAX_PATTERNS (100)
        assert len(policy._compiled_allowed) <= 100

    def test_malicious_regex_pattern(self):
        """Test that potentially malicious regex patterns don't cause slowdown."""
        # This pattern could cause exponential backtracking with naive regex
        config = ScopeConfig(
            allowed_domains=["a*b*c*d*e"],
        )
        policy = ScopePolicy(config)

        # Should complete quickly even with complex input
        start = time.time()
        test_input = "a" * 50 + "x"  # Input that could trigger backtracking
        policy.is_allowed(f"https://{test_input}/page")
        elapsed = time.time() - start

        # Should complete in well under 1 second
        assert elapsed < 0.5

    def test_safe_regex_conversion(self):
        """Test that glob patterns are converted safely."""
        config = ScopeConfig(
            allowed_domains=["*.example.com"],
        )
        policy = ScopePolicy(config)

        # Normal matching should still work
        assert policy.is_allowed("https://sub.example.com/page")
        assert policy.is_allowed("https://deep-sub.example.com/page")


class TestNormalizeUrl:
    """Tests for URL normalization."""

    def test_relative_url(self):
        """Test relative URL resolution."""
        assert normalize_url(
            "app.js", "https://example.com/path/"
        ) == "https://example.com/path/app.js"

    def test_protocol_relative_url(self):
        """Test protocol-relative URL handling."""
        assert normalize_url(
            "//cdn.example.com/lib.js", "https://example.com/"
        ) == "https://cdn.example.com/lib.js"

    def test_fragment_removal(self):
        """Test fragment removal."""
        assert normalize_url(
            "https://example.com/page#section"
        ) == "https://example.com/page"

    def test_domain_lowercase(self):
        """Test domain lowercasing."""
        assert normalize_url(
            "https://EXAMPLE.COM/path"
        ) == "https://example.com/path"


class TestIsJsUrl:
    """Tests for JS URL detection."""

    def test_js_extensions(self):
        """Test detection of JS extensions."""
        assert is_js_url("https://example.com/app.js")
        assert is_js_url("https://example.com/module.mjs")
        assert is_js_url("https://example.com/component.jsx")
        # .ts and .tsx are excluded from web URL detection
        # (they are handled separately by LocalCollector)
        assert not is_js_url("https://example.com/types.ts")
        assert not is_js_url("https://example.com/component.tsx")

    def test_non_js_extensions(self):
        """Test non-JS files are not detected."""
        assert not is_js_url("https://example.com/style.css")
        assert not is_js_url("https://example.com/image.png")
        assert not is_js_url("https://example.com/page.html")

    def test_chunk_patterns(self):
        """Test detection of webpack/vite chunks."""
        assert is_js_url("https://example.com/static/js/main.chunk.js")
        assert is_js_url("https://example.com/_next/static/chunks/webpack.js")
        assert is_js_url("https://example.com/assets/index.a1b2c3d4.js")

