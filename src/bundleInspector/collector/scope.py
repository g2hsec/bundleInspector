"""
Scope policy engine for filtering URLs.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import unquote, urljoin, urlunparse

from bundleInspector.config import ScopeConfig, ThirdPartyPolicy
from bundleInspector.core.url_utils import safe_urlparse as urlparse


class ScopePolicy:
    """
    Scope policy engine for URL filtering.

    Determines which URLs are in scope and whether they are
    first-party or third-party.
    """

    # Security limits to prevent ReDoS and resource exhaustion.
    # A glob compiles to overlapping `(?:charclass)*` groups; k wildcards over a hostile hostname
    # that repeats a class char (`*a*a*a*a*a` vs `aaaa...!`) backtrack O(n^k). Cap wildcards low so
    # the worst case stays quadratic, AND cap the MATCH INPUT so that quadratic stays tiny --
    # together they keep matching near-constant (ReDoS-safe on Python 3.10+, which lacks atomic
    # groups / possessive quantifiers).
    MAX_PATTERN_LENGTH = 256
    MAX_WILDCARDS_PER_PATTERN = 2
    MAX_PATTERNS = 100
    MAX_MATCH_INPUT_LENGTH = 255  # a DNS hostname is <=253 chars; longer inputs are invalid

    def __init__(self, config: ScopeConfig):
        self.config = config
        self.pattern_diagnostics: list[dict[str, Any]] = []
        self._compiled_allowed = self._compile_patterns(config.allowed_domains, "allowed_domains")
        self._compiled_denied = self._compile_patterns(config.denied_domains, "denied_domains")
        self._compiled_cdn = self._compile_patterns(config.cdn_patterns, "cdn_patterns")

    def recompile(self) -> None:
        """Recompile patterns from current config state."""
        self.pattern_diagnostics = []
        self._compiled_allowed = self._compile_patterns(
            self.config.allowed_domains, "allowed_domains"
        )
        self._compiled_denied = self._compile_patterns(
            self.config.denied_domains, "denied_domains"
        )
        self._compiled_cdn = self._compile_patterns(self.config.cdn_patterns, "cdn_patterns")

    def _compile_patterns(
        self,
        patterns: list[str],
        category: str = "patterns",
    ) -> list[re.Pattern]:
        """
        Compile glob patterns to regex safely.

        Uses non-backtracking patterns to prevent ReDoS attacks.
        Applies security limits to prevent resource exhaustion.
        """
        compiled = []

        # Limit number of patterns, but make the rejected portion observable. A silently
        # truncated allowlist changes scope semantics and can otherwise look like a clean denial.
        safe_patterns = patterns[:self.MAX_PATTERNS]
        if len(patterns) > self.MAX_PATTERNS:
            self.pattern_diagnostics.append({
                "category": category,
                "reason": "pattern_limit",
                "accepted": self.MAX_PATTERNS,
                "rejected": len(patterns) - self.MAX_PATTERNS,
            })

        for index, pattern in enumerate(safe_patterns):
            # Skip patterns that are too long
            if len(pattern) > self.MAX_PATTERN_LENGTH:
                self.pattern_diagnostics.append({
                    "category": category,
                    "index": index,
                    "pattern": pattern,
                    "reason": "pattern_too_long",
                })
                continue

            # Skip patterns with too many wildcards
            if pattern.count('*') > self.MAX_WILDCARDS_PER_PATTERN:
                self.pattern_diagnostics.append({
                    "category": category,
                    "index": index,
                    "pattern": pattern,
                    "reason": "too_many_wildcards",
                })
                continue

            try:
                # Build regex safely to prevent ReDoS
                regex = self._glob_to_safe_regex(pattern)
                compiled.append(re.compile(regex, re.IGNORECASE))
            except re.error as exc:
                self.pattern_diagnostics.append({
                    "category": category,
                    "index": index,
                    "pattern": pattern,
                    "reason": "invalid_pattern",
                    "detail": str(exc),
                })

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

    @staticmethod
    def _canonicalize_scope_path(path: str) -> str | None:
        """Return the path shape an HTTP server is likely to authorize.

        Scope checks must not approve a raw path that becomes denied after percent decoding or
        dot-segment processing. Repeated decoding is intentionally conservative: a path requiring
        several decode passes is ambiguous across proxies/servers and is safer to reject.
        """
        if not isinstance(path, str) or re.search(r"%(?![0-9A-Fa-f]{2})", path):
            return None

        decoded = path
        for _ in range(4):
            try:
                next_value = unquote(decoded, errors="strict")
            except (UnicodeError, ValueError):
                return None
            if next_value == decoded:
                break
            decoded = next_value
        else:
            return None

        decoded = unicodedata.normalize("NFKC", decoded).replace("\\", "/")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded):
            return None

        segments: list[str] = []
        for raw_segment in decoded.split("/"):
            # Matrix parameters are stripped for authorization comparison. This contains common
            # `/allowed/..;/denied` and `/denied;param` proxy/backend interpretation drift.
            segment = raw_segment.partition(";")[0]
            if not segment or segment == ".":
                continue
            if segment == "..":
                if segments:
                    segments.pop()
                continue
            segments.append(segment)
        return "/" + "/".join(segments)

    @classmethod
    def _path_prefix_matches(cls, path: str, configured_prefix: str) -> bool:
        """Match a configured path at a segment boundary, not an arbitrary character prefix."""
        canonical_path = cls._canonicalize_scope_path(path)
        canonical_prefix = cls._canonicalize_scope_path(configured_prefix)
        if canonical_path is None or canonical_prefix is None:
            return False
        if not configured_prefix:
            return True
        prefix = canonical_prefix.rstrip("/")
        if not prefix:
            return canonical_path.startswith("/")
        return canonical_path == prefix or canonical_path.startswith(prefix + "/")

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
        path = self._canonicalize_scope_path(parsed.path)
        if not domain or path is None:
            return False

        # Check domain denial first (explicit deny wins)
        if self._matches_patterns(domain, self._compiled_denied):
            return False

        # Check path denial
        for denied_path in self.config.denied_paths:
            if self._path_prefix_matches(path, denied_path):
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
                if self._path_prefix_matches(path, allowed_path):
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
        # Refuse to run the globs on an over-long (invalid) hostname so a crafted value cannot
        # amplify a wildcard pattern's bounded backtracking into a hang (ReDoS defense).
        if len(value) > self.MAX_MATCH_INPUT_LENGTH:
            return False
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
    ) -> ScopePolicy:
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
    base_url: str | None = None,
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
    from bundleInspector.core.url_utils import safe_urlparse as urlparse

    def invalid(message: str) -> str:
        if strict:
            raise URLValidationError(message)
        return ""

    if not isinstance(url, str):
        return invalid("URL must be a string")

    url = url.strip()
    if not url or any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return invalid("URL is empty or contains control characters")
    if base_url is not None:
        if not isinstance(base_url, str):
            return invalid("Base URL must be a string")
        base_url = base_url.strip()
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in base_url):
            return invalid("Base URL contains control characters")

    # Security: Block dangerous URL schemes
    url_lower = url.lower()
    for scheme in BLOCKED_SCHEMES:
        if url_lower.startswith(f"{scheme}:"):
            return invalid(f"Blocked URL scheme: {scheme}")

    try:
        # Handle relative and protocol-relative URLs. Detect a scheme case-insensitively so an
        # uppercase absolute URL is not accidentally joined as a relative path.
        if url.startswith("//"):
            if base_url:
                parsed_base = urlparse(base_url)
                if parsed_base.scheme not in ALLOWED_SCHEMES:
                    return invalid("Base URL has no supported scheme")
                url = f"{parsed_base.scheme}:{url}"
            else:
                url = f"https:{url}"
        elif base_url and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", url) is None:
            url = urljoin(base_url, url)

        # Parse and normalize. safe_urlparse contains malformed authorities, while the explicit
        # authority checks below convert them to this function's stable failure contract.
        parsed = urlparse(url)
    except (TypeError, ValueError, UnicodeError) as exc:
        return invalid(f"Malformed URL: {exc}")

    # Validate scheme
    scheme = (parsed.scheme or '').lower()
    if scheme and scheme not in ALLOWED_SCHEMES:
        return invalid(f"Unsupported URL scheme: {scheme}")

    # Schemeless input (e.g., "example.com/script.js") produces empty scheme
    if not scheme and not url.startswith("//"):
        return invalid(f"Missing URL scheme: {url}")

    # Check for scheme without authority (e.g., "http:path")
    if scheme and not parsed.netloc:
        return invalid(f"URL has no authority: {url}")

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
