"""
Scope policy engine for filtering URLs.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Optional
from urllib.parse import urlparse

from bundleInspector.config import ScopeConfig, ThirdPartyPolicy


class ScopePolicy:
    """
    Scope policy engine for URL filtering.

    Determines which URLs are in scope and whether they are
    first-party or third-party.
    """

    # Security limits to prevent ReDoS and resource exhaustion
    MAX_PATTERN_LENGTH = 256
    MAX_WILDCARDS_PER_PATTERN = 5
    MAX_PATTERNS = 100

    def __init__(self, config: ScopeConfig):
        self.config = config
        self._compiled_allowed = self._compile_patterns(config.allowed_domains)
        self._compiled_denied = self._compile_patterns(config.denied_domains)
        self._compiled_cdn = self._compile_patterns(config.cdn_patterns)

    def recompile(self) -> None:
        """Recompile patterns from current config state."""
        self._compiled_allowed = self._compile_patterns(self.config.allowed_domains)
        self._compiled_denied = self._compile_patterns(self.config.denied_domains)
        self._compiled_cdn = self._compile_patterns(self.config.cdn_patterns)

    def _compile_patterns(self, patterns: list[str]) -> list[re.Pattern]:
        """
        Compile glob patterns to regex safely.

        Uses non-backtracking patterns to prevent ReDoS attacks.
        Applies security limits to prevent resource exhaustion.
        """
        compiled = []

        # Limit number of patterns
        safe_patterns = patterns[:self.MAX_PATTERNS]

        for pattern in safe_patterns:
            # Skip patterns that are too long
            if len(pattern) > self.MAX_PATTERN_LENGTH:
                continue

            # Skip patterns with too many wildcards
            if pattern.count('*') > self.MAX_WILDCARDS_PER_PATTERN:
                continue

            try:
                # Build regex safely to prevent ReDoS
                regex = self._glob_to_safe_regex(pattern)
                compiled.append(re.compile(regex, re.IGNORECASE))
            except re.error:
                # Skip invalid patterns
                pass

        return compiled

    def _glob_to_safe_regex(self, pattern: str) -> str:
        """
        Convert glob pattern to safe regex.

        Prevents ReDoS by using possessive-like matching.
        For domain patterns, * at start matches subdomains (including dots).
        """
        result = []
        i = 0
        pattern_len = len(pattern)

        while i < pattern_len:
            char = pattern[i]
            if char == '*':
                # Check for ** (match anything including dots)
                if i + 1 < pattern_len and pattern[i + 1] == '*':
                    # ** matches anything - use atomic-like pattern
                    result.append('(?:[a-zA-Z0-9._:-])*')
                    i += 2
                elif i == 0:
                    # * at start of pattern - match subdomains (includes dots)
                    # This handles patterns like "*.example.com"
                    result.append('(?:[a-zA-Z0-9._:-])*')
                    i += 1
                else:
                    # Single * in middle/end - match single segment (no dots)
                    result.append('(?:[a-zA-Z0-9_:-])*')
                    i += 1
            elif char == '?':
                # ? matches single character (not dot)
                result.append('[a-zA-Z0-9_-]')
                i += 1
            elif char in '.^$+{}[]|()\\':
                # Escape regex special characters
                result.append('\\' + char)
                i += 1
            else:
                result.append(char)
                i += 1

        return f'^{"".join(result)}$'

    def is_allowed(self, url: str) -> bool:
        """
        Check if URL is allowed by scope policy.

        Args:
            url: URL to check

        Returns:
            True if URL is in scope
        """
        parsed = urlparse(url)

        if not url or not parsed.netloc:
            return False

        domain = (parsed.hostname or "").lower()
        path = parsed.path

        # Check domain denial first (explicit deny wins)
        if self._matches_patterns(domain, self._compiled_denied):
            return False

        # Check path denial
        for denied_path in self.config.denied_paths:
            if path.startswith(denied_path):
                return False

        # If no allowed domains specified, allow all (except denied)
        if not self.config.allowed_domains:
            # But check third-party policy
            if self.config.third_party_policy == ThirdPartyPolicy.SKIP:
                if self._is_cdn(domain):
                    return False
            return True

        # Check domain allowance
        if not self._matches_patterns(domain, self._compiled_allowed):
            # Not in allowed list - check third-party policy
            if self.config.third_party_policy == ThirdPartyPolicy.SKIP:
                return False
            if self.config.third_party_policy == ThirdPartyPolicy.TAG_ONLY:
                # TAG_ONLY: allow but will be tagged as third-party
                return True
            # ANALYZE: allow for analysis
            return True

        # Check path allowance (if specified)
        if self.config.allowed_paths:
            for allowed_path in self.config.allowed_paths:
                if path.startswith(allowed_path):
                    return True
            return False

        return True

    def is_first_party(self, url: str) -> bool:
        """
        Check if URL is first-party (vs third-party CDN etc).

        Args:
            url: URL to check

        Returns:
            True if URL is first-party
        """
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        # Check if matches allowed domains
        if self._matches_patterns(domain, self._compiled_allowed):
            return True

        # Check if it's a known CDN
        if self._is_cdn(domain):
            return False

        # If no allowed domains, consider it first-party
        if not self.config.allowed_domains:
            return True

        return False

    def _matches_patterns(
        self,
        value: str,
        patterns: list[re.Pattern]
    ) -> bool:
        """Check if value matches any pattern."""
        for pattern in patterns:
            if pattern.match(value):
                return True
        return False

    def _is_cdn(self, domain: str) -> bool:
        """Check if domain is a known CDN."""
        return self._matches_patterns(domain, self._compiled_cdn)

    def get_scope_tag(self, url: str) -> str:
        """
        Get scope classification tag for URL.

        Returns:
            "first_party", "third_party", or "cdn"
        """
        if self.is_first_party(url):
            return "first_party"

        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        if self._is_cdn(domain):
            return "cdn"

        return "third_party"

    @classmethod
    def from_seed_urls(
        cls,
        seed_urls: list[str],
        include_subdomains: bool = True,
        third_party_policy: ThirdPartyPolicy = ThirdPartyPolicy.TAG_ONLY,
    ) -> "ScopePolicy":
        """
        Create scope policy from seed URLs.

        Args:
            seed_urls: List of seed URLs
            include_subdomains: Whether to include subdomains
            third_party_policy: How to handle third-party JS

        Returns:
            ScopePolicy instance
        """
        allowed_domains = []

        for url in seed_urls:
            parsed = urlparse(url)
            domain = parsed.hostname

            if domain:
                allowed_domains.append(domain)
                if include_subdomains:
                    allowed_domains.append(f"*.{domain}")
                netloc = parsed.netloc.lower() if parsed.netloc else ""
                if netloc and netloc != domain:
                    allowed_domains.append(netloc)

        config = ScopeConfig(
            allowed_domains=allowed_domains,
            include_subdomains=include_subdomains,
            third_party_policy=third_party_policy,
        )

        return cls(config)


class URLValidationError(ValueError):
    """Raised when URL validation fails."""
    pass


# Blocked URL schemes (security risk)
BLOCKED_SCHEMES = frozenset({
    'javascript', 'data', 'vbscript', 'file',
})

# Allowed URL schemes
ALLOWED_SCHEMES = frozenset({'http', 'https'})


def normalize_url(
    url: str,
    base_url: Optional[str] = None,
    strict: bool = False,
) -> str:
    """
    Normalize a URL with security validation.

    Args:
        url: URL to normalize
        base_url: Base URL for relative URLs
        strict: If True, raise exception for invalid URLs

    Returns:
        Normalized absolute URL

    Raises:
        URLValidationError: If strict=True and URL is invalid/blocked
    """
    from urllib.parse import urljoin, urlparse, urlunparse

    # Security: Block dangerous URL schemes
    url_lower = url.lower().strip()
    for scheme in BLOCKED_SCHEMES:
        if url_lower.startswith(f"{scheme}:"):
            if strict:
                raise URLValidationError(f"Blocked URL scheme: {scheme}")
            return ""

    # Handle relative URLs
    if base_url and not url.startswith(("http://", "https://", "//")):
        url = urljoin(base_url, url)
    elif url.startswith("//"):
        # Protocol-relative URL
        if base_url:
            parsed_base = urlparse(base_url)
            url = f"{parsed_base.scheme}:{url}"
        else:
            url = f"https:{url}"

    # Parse and normalize
    parsed = urlparse(url)

    # Validate scheme
    scheme = (parsed.scheme or '').lower()
    if scheme and scheme not in ALLOWED_SCHEMES:
        if strict:
            raise URLValidationError(f"Unsupported URL scheme: {scheme}")
        return ""

    # Schemeless input (e.g., "example.com/script.js") produces empty scheme
    if not scheme and not url.startswith("//"):
        if strict:
            raise URLValidationError(f"Missing URL scheme: {url}")
        return ""

    # Check for scheme without authority (e.g., "http:path")
    if scheme and not parsed.netloc:
        if strict:
            raise URLValidationError(f"URL has no authority: {url}")
        return ""

    # Remove fragments
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        ""  # No fragment
    ))

    return normalized


def is_js_url(url: str) -> bool:
    """
    Check if URL likely points to a JavaScript file.

    Args:
        url: URL to check

    Returns:
        True if URL appears to be JS
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Common JS extensions
    js_extensions = (".js", ".mjs", ".cjs", ".jsx")

    if any(path.endswith(ext) for ext in js_extensions):
        return True

    # Check for chunk patterns (webpack/vite) ??require JS extension
    chunk_patterns = [
        r"/chunk[-.][\w.-]*\.(?:js|mjs|cjs)(?:\?|$)",
        r"/bundle[-.][\w.-]*\.(?:js|mjs|cjs)(?:\?|$)",
        r"\.chunk\.(?:js|mjs|cjs)(?:\?|$)",
        r"\.bundle\.(?:js|mjs|cjs)(?:\?|$)",
        r"/static/js/[^/]+\.js",
        r"/_next/static/chunks/[^/]+\.js",
        r"/assets/.*\.[a-f0-9]+\.js",
    ]

    for pattern in chunk_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True

    return False

