"""Tests for security utilities."""

import uuid
from pathlib import Path

import pytest
from tests.fixtures.fake_secrets import FAKE_MASK_VALUE_LONG, FAKE_MASK_VALUE_SHORT
from bundleInspector.core.security import (
    is_url_safe,
    is_ip_blocked,
    is_host_blocked,
    is_path_safe,
    sanitize_url,
    sanitize_path,
    mask_sensitive_value,
)

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_dir() -> Path:
    """Create a unique workspace-local directory for path tests."""
    path = TEST_TMP_ROOT / f"{uuid.uuid4().hex}_dir"
    path.mkdir(parents=True, exist_ok=True)
    return path


class TestSSRFProtection:
    """Tests for SSRF protection."""

    def test_safe_public_url(self):
        """Test that public URLs are allowed."""
        is_safe, reason = is_url_safe("https://example.com/api/data", resolve_dns=False)
        assert is_safe is True

    def test_block_localhost(self):
        """Test that localhost is blocked."""
        is_safe, reason = is_url_safe("http://localhost/admin", resolve_dns=False)
        assert is_safe is False
        assert "Blocked host" in reason

    def test_block_127_0_0_1(self):
        """Test that 127.0.0.1 is blocked."""
        is_safe, reason = is_url_safe("http://127.0.0.1:8080/", resolve_dns=False)
        assert is_safe is False

    def test_block_private_ip_10(self):
        """Test that 10.x.x.x is blocked."""
        is_safe, reason = is_url_safe("http://10.0.0.1/internal", resolve_dns=False)
        assert is_safe is False

    def test_block_private_ip_172(self):
        """Test that 172.16.x.x is blocked."""
        is_safe, reason = is_url_safe("http://172.16.0.1/", resolve_dns=False)
        assert is_safe is False

    def test_block_private_ip_192(self):
        """Test that 192.168.x.x is blocked."""
        is_safe, reason = is_url_safe("http://192.168.1.1/", resolve_dns=False)
        assert is_safe is False

    def test_block_aws_metadata(self):
        """Test that AWS metadata endpoint is blocked."""
        is_safe, reason = is_url_safe(
            "http://169.254.169.254/latest/meta-data/",
            resolve_dns=False
        )
        assert is_safe is False

    def test_block_javascript_scheme(self):
        """Test that javascript: scheme is blocked."""
        is_safe, reason = is_url_safe("javascript:alert(1)", resolve_dns=False)
        assert is_safe is False
        assert "Blocked scheme" in reason

    def test_block_data_scheme(self):
        """Test that data: scheme is blocked."""
        is_safe, reason = is_url_safe(
            "data:text/html,<script>alert(1)</script>",
            resolve_dns=False
        )
        assert is_safe is False

    def test_block_file_scheme(self):
        """Test that file: scheme is blocked."""
        is_safe, reason = is_url_safe("file:///etc/passwd", resolve_dns=False)
        assert is_safe is False

    def test_block_empty_url(self):
        """Test that empty URL is blocked."""
        is_safe, reason = is_url_safe("", resolve_dns=False)
        assert is_safe is False

    def test_sanitize_url_returns_none_for_blocked(self):
        """Test that sanitize_url returns None for blocked URLs."""
        result = sanitize_url("http://localhost/admin")
        assert result is None

    def test_sanitize_url_returns_url_for_safe(self):
        """Test that sanitize_url returns URL for safe URLs."""
        result = sanitize_url("https://example.com/api")
        assert result == "https://example.com/api"


class TestIPBlocking:
    """Tests for IP address blocking."""

    def test_block_loopback_v4(self):
        """Test that IPv4 loopback is blocked."""
        assert is_ip_blocked("127.0.0.1") is True
        assert is_ip_blocked("127.0.0.255") is True

    def test_block_loopback_v6(self):
        """Test that IPv6 loopback is blocked."""
        assert is_ip_blocked("::1") is True

    def test_block_link_local(self):
        """Test that link-local addresses are blocked."""
        assert is_ip_blocked("169.254.0.1") is True
        assert is_ip_blocked("169.254.169.254") is True

    def test_allow_public_ip(self):
        """Test that public IPs are allowed."""
        assert is_ip_blocked("8.8.8.8") is False
        assert is_ip_blocked("1.1.1.1") is False

    def test_invalid_ip_returns_false(self):
        """Test that invalid IP returns False (not blocked)."""
        assert is_ip_blocked("not-an-ip") is False


class TestAllowPrivateIps:
    """Opt-in SSRF bypass for authorized internal scanning (--allow-private-ips)."""

    def test_private_ranges_permitted_when_flag_set(self):
        # RFC1918 / CGNAT / IPv6-ULA are blocked by default but allowed with the opt-in.
        for ip in ("10.100.166.159", "192.168.1.1", "172.16.0.1", "100.64.0.1", "fc00::1"):
            assert is_ip_blocked(ip) is True                       # default: blocked
            assert is_ip_blocked(ip, allow_private_ips=True) is False  # opt-in: allowed

    def test_loopback_and_metadata_stay_blocked_with_flag(self):
        # The opt-in must NOT open loopback / link-local (cloud metadata) / multicast / reserved.
        for ip in ("127.0.0.1", "::1", "169.254.169.254", "169.254.0.1",
                   "0.0.0.0", "224.0.0.1", "240.0.0.1"):
            assert is_ip_blocked(ip, allow_private_ips=True) is True

    def test_is_url_safe_allows_private_target_with_flag(self):
        safe, _ = is_url_safe("http://10.100.166.159:18033/app.js",
                              resolve_dns=False, allow_private_ips=True)
        assert safe is True
        # ...but still refuses without the flag,
        blocked, _ = is_url_safe("http://10.100.166.159:18033/app.js", resolve_dns=False)
        assert blocked is False

    def test_is_url_safe_still_blocks_metadata_and_localhost_with_flag(self):
        for url in ("http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:8080/", "http://localhost/admin"):
            safe, _ = is_url_safe(url, resolve_dns=False, allow_private_ips=True)
            assert safe is False

    def test_config_default_off(self):
        from bundleInspector.config import Config
        assert Config().scope.allow_private_ips is False


class TestHostBlocking:
    """Tests for hostname blocking."""

    def test_block_localhost(self):
        """Test that localhost variants are blocked."""
        assert is_host_blocked("localhost") is True
        assert is_host_blocked("LOCALHOST") is True
        assert is_host_blocked("localhost.localdomain") is True

    def test_block_metadata_endpoints(self):
        """Test that cloud metadata endpoints are blocked."""
        assert is_host_blocked("metadata.google.internal") is True
        assert is_host_blocked("metadata.goog") is True

    def test_allow_public_domain(self):
        """Test that public domains are allowed."""
        assert is_host_blocked("example.com") is False
        assert is_host_blocked("google.com") is False

    def test_block_empty_host(self):
        """Test that empty hostname is blocked."""
        assert is_host_blocked("") is True


class TestPathTraversalProtection:
    """Tests for path traversal protection."""

    def test_safe_path_within_base(self):
        """Test that paths within base are allowed."""
        base = _make_test_dir()
        test_file = base / "test.js"
        test_file.touch()

        is_safe, reason = is_path_safe(test_file, [base])
        assert is_safe is True

    def test_block_path_outside_base(self):
        """Test that paths outside base are blocked."""
        base = _make_test_dir()

        is_safe, reason = is_path_safe(Path("/etc/passwd"), [base])
        assert is_safe is False

    def test_block_traversal_attack(self):
        """Test that path traversal attacks are blocked."""
        base = _make_test_dir()

        # Create a subdir
        subdir = base / "subdir"
        subdir.mkdir()

        # Try to escape with ..
        traversal_path = subdir / ".." / ".." / "etc" / "passwd"

        is_safe, reason = is_path_safe(traversal_path, [base])
        assert is_safe is False

    def test_sanitize_path_returns_none_for_blocked(self):
        """Test that sanitize_path returns None for blocked paths."""
        base = _make_test_dir()

        result = sanitize_path("/etc/passwd", [base])
        assert result is None

    def test_sanitize_path_returns_resolved_for_safe(self):
        """Test that sanitize_path returns resolved path for safe paths."""
        base = _make_test_dir()
        test_file = base / "test.js"
        test_file.touch()

        result = sanitize_path(test_file, [base])
        assert result is not None
        assert result == test_file.resolve()


class TestSensitiveValueMasking:
    """Tests for sensitive value masking."""

    def test_mask_long_value(self):
        """Test masking a long value."""
        result = mask_sensitive_value(FAKE_MASK_VALUE_LONG)
        assert result.startswith("sk_l")
        assert result.endswith("cdef")
        assert "*" in result

    def test_mask_short_value(self):
        """Test masking a short value."""
        result = mask_sensitive_value("secret")
        assert result == "******"

    def test_mask_empty_value(self):
        """Test masking an empty value."""
        result = mask_sensitive_value("")
        assert result == ""

    def test_mask_custom_chars(self):
        """Test masking with custom visible chars."""
        result = mask_sensitive_value(
            FAKE_MASK_VALUE_SHORT,
            visible_start=2,
            visible_end=2,
        )
        assert result.startswith("sk")
        assert result.endswith("90")

