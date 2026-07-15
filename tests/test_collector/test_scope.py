"""Tests for scope policy."""

import time

import pytest

from bundleInspector.collector.scope import (
    ScopePolicy,
    URLValidationError,
    is_js_url,
    normalize_url,
)
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
        assert policy.is_allowed("https://example.com/administrator")

    def test_allowed_path_matches_only_at_segment_boundary(self):
        policy = ScopePolicy(ScopeConfig(
            allowed_domains=["example.com"],
            allowed_paths=["/app"],
            third_party_policy=ThirdPartyPolicy.SKIP,
        ))

        assert policy.is_allowed("https://example.com/app")
        assert policy.is_allowed("https://example.com/app/settings")
        assert not policy.is_allowed("https://example.com/apple")

    @pytest.mark.parametrize(
        "path",
        [
            "/public/../admin/users",
            "/public/%2e%2e/admin/users",
            "/public/%252e%252e/admin/users",
            "/public/..;/admin/users",
            "/public%2f..%2fadmin/users",
            "/public\\..\\admin/users",
        ],
    )
    def test_scope_canonicalizes_paths_before_policy_matching(self, path):
        policy = ScopePolicy(ScopeConfig(
            allowed_domains=["example.com"],
            allowed_paths=["/public"],
            denied_paths=["/admin"],
            third_party_policy=ThirdPartyPolicy.SKIP,
        ))

        assert not policy.is_allowed(f"https://example.com{path}")

    @pytest.mark.parametrize(
        "path",
        ["/public/%", "/public/%0", "/public/%00/admin", "/public/%FF/admin"],
    )
    def test_scope_rejects_malformed_or_control_encoded_paths(self, path):
        policy = ScopePolicy(ScopeConfig(
            allowed_domains=["example.com"],
            allowed_paths=["/public"],
            third_party_policy=ThirdPartyPolicy.SKIP,
        ))

        assert not policy.is_allowed(f"https://example.com{path}")

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
        with pytest.raises(ValueError, match="invalid domain pattern"):
            ScopeConfig(allowed_domains=[long_pattern])
        config = ScopeConfig.model_construct(allowed_domains=[long_pattern])
        policy = ScopePolicy(config)

        # Pattern should be ignored
        assert len(policy._compiled_allowed) == 0
        assert policy.pattern_diagnostics[0]["reason"] == "pattern_too_long"

    def test_wildcard_count_limit(self):
        """Test that patterns with too many wildcards are rejected."""
        many_wildcards = "*.*.*.*.*.*"  # 6 wildcards
        with pytest.raises(ValueError, match="too many wildcards"):
            ScopeConfig(allowed_domains=[many_wildcards])
        config = ScopeConfig.model_construct(allowed_domains=[many_wildcards])
        policy = ScopePolicy(config)

        # Pattern should be ignored
        assert len(policy._compiled_allowed) == 0
        assert policy.pattern_diagnostics[0]["reason"] == "too_many_wildcards"

    def test_pattern_count_limit(self):
        """Test that excess patterns are truncated."""
        patterns = [f"domain{i}.com" for i in range(150)]
        with pytest.raises(ValueError, match="at most 100"):
            ScopeConfig(allowed_domains=patterns)
        config = ScopeConfig.model_construct(allowed_domains=patterns)
        policy = ScopePolicy(config)

        # Should be limited to MAX_PATTERNS (100)
        assert len(policy._compiled_allowed) <= 100
        assert policy.pattern_diagnostics == [{
            "category": "allowed_domains",
            "reason": "pattern_limit",
            "accepted": 100,
            "rejected": 50,
        }]

    def test_malicious_regex_pattern(self):
        """Test that potentially malicious regex patterns don't cause slowdown."""
        # This pattern could cause exponential backtracking with naive regex
        with pytest.raises(ValueError, match="too many wildcards"):
            ScopeConfig(allowed_domains=["a*b*c*d*e"])
        config = ScopeConfig.model_construct(allowed_domains=["a*b*c*d*e"])
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

    def test_whitespace_is_removed_from_the_actual_candidate(self):
        assert normalize_url(
            "  app.js  ", " https://example.com/path/ "
        ) == "https://example.com/path/app.js"

    @pytest.mark.parametrize("candidate", ["//[bad", " //[bad", "https://[bad/path"])
    def test_malformed_authority_never_escapes(self, candidate):
        assert normalize_url(candidate, "https://example.com/") == ""
        with pytest.raises(URLValidationError):
            normalize_url(candidate, "https://example.com/", strict=True)

    def test_control_characters_fail_closed(self):
        assert normalize_url("https://example.com/a\nb") == ""
        with pytest.raises(URLValidationError):
            normalize_url("https://example.com/a\nb", strict=True)

    def test_control_characters_in_base_url_fail_closed(self):
        assert normalize_url("app.js", "https://example.com/a\nb/") == ""
        with pytest.raises(URLValidationError):
            normalize_url("app.js", "https://example.com/a\nb/", strict=True)

    def test_uppercase_absolute_scheme_is_not_joined_as_relative(self):
        assert normalize_url(
            "HTTPS://EXAMPLE.COM/app.js", "https://other.example/base/"
        ) == "https://example.com/app.js"


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


def test_scope_no_redos_on_hostile_hostname():
    """Many overlapping wildcards over a hostname that repeats the wildcard-class char (the
    catastrophic-backtracking shape `*a*a*a*a*a` vs `aaaa...!`) must not hang is_allowed."""
    with pytest.raises(ValueError, match="too many wildcards"):
        ScopeConfig(denied_domains=["*a*a*a*a*a"])
    # Legacy/constructed inputs remain bounded at the lower policy layer as defense in depth.
    config = ScopeConfig.model_construct(denied_domains=["*a*a*a*a*a"])
    policy = ScopePolicy(config)
    start = time.time()
    policy.is_allowed("http://" + "a" * 250 + "!/x.js")
    assert time.time() - start < 1.0


def test_scope_rejects_overlong_match_input():
    """An over-long (invalid) hostname is never fed to the wildcard regex (input-length ReDoS guard)."""
    policy = ScopePolicy(ScopeConfig(allowed_domains=["*.example.com"]))
    assert policy._matches_patterns("a" * 300, policy._compiled_allowed) is False


def test_scope_two_wildcard_pattern_still_works():
    """The ReDoS fix keeps common patterns: a 2-wildcard glob still compiles and matches."""
    policy = ScopePolicy(ScopeConfig(allowed_domains=["*.*.example.com"]))
    assert len(policy._compiled_allowed) == 1
    assert policy.is_allowed("https://a.b.example.com/x") is True
