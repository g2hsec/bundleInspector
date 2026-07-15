"""
Security utilities for BundleInspector.

Provides protection against SSRF, path traversal, and other attacks.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


# =============================================================================
# SSRF Protection
# =============================================================================

# Blocked hostnames (case-insensitive)
BLOCKED_HOSTS = frozenset({
    'localhost',
    'localhost.localdomain',
    'localhost4',
    'localhost6',
    # Cloud metadata endpoints
    'metadata.google.internal',
    'metadata.goog',
    'kubernetes.default.svc',
    'kubernetes.default',
})

# Blocked IP networks (private, loopback, link-local, etc.)
BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),        # Current network
    ipaddress.ip_network('10.0.0.0/8'),       # Private A
    ipaddress.ip_network('100.64.0.0/10'),    # Carrier-grade NAT
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local (AWS metadata)
    ipaddress.ip_network('172.16.0.0/12'),    # Private B
    ipaddress.ip_network('192.0.0.0/24'),     # IETF protocol assignments
    ipaddress.ip_network('192.0.2.0/24'),     # TEST-NET-1
    ipaddress.ip_network('192.168.0.0/16'),   # Private C
    ipaddress.ip_network('198.18.0.0/15'),    # Benchmarking
    ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),   # TEST-NET-3
    ipaddress.ip_network('224.0.0.0/4'),      # Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # Reserved
    ipaddress.ip_network('255.255.255.255/32'),  # Broadcast
    # IPv6
    ipaddress.ip_network('::1/128'),          # Loopback
    ipaddress.ip_network('::/128'),           # Unspecified
    ipaddress.ip_network('::ffff:0:0/96'),    # IPv4-mapped
    ipaddress.ip_network('fc00::/7'),         # Unique local
    ipaddress.ip_network('fe80::/10'),        # Link-local
    ipaddress.ip_network('ff00::/8'),         # Multicast
]

# Subset of BLOCKED_NETWORKS that are ordinary private/internal ranges (RFC1918, CGNAT,
# IPv6 ULA). These -- and ONLY these -- are permitted when allow_private_ips is set (for
# authorized internal/dev-server scanning). Loopback, link-local (incl. cloud metadata
# 169.254.169.254), multicast, reserved, and TEST-NET ranges stay blocked regardless.
PRIVATE_NETWORKS = frozenset({
    ipaddress.ip_network('10.0.0.0/8'),       # Private A
    ipaddress.ip_network('172.16.0.0/12'),    # Private B
    ipaddress.ip_network('192.168.0.0/16'),   # Private C
    ipaddress.ip_network('100.64.0.0/10'),    # Carrier-grade NAT
    ipaddress.ip_network('fc00::/7'),         # IPv6 unique-local
})

# Dangerous URL schemes
BLOCKED_SCHEMES = frozenset({
    'javascript', 'data', 'vbscript', 'file',
    'ftp', 'gopher', 'ldap', 'dict', 'sftp',
})

# Allowed URL schemes
ALLOWED_SCHEMES = frozenset({'http', 'https'})


def is_ip_blocked(ip_str: str, allow_private_ips: bool = False) -> bool:
    """
    Check if an IP address is in a blocked network.

    Args:
        ip_str: IP address string
        allow_private_ips: If True, permit RFC1918/CGNAT/ULA private ranges (for authorized
            internal scanning); loopback / link-local (metadata) / multicast / reserved stay blocked.

    Returns:
        True if blocked, False if allowed
    """
    ip = _parse_ip_literal(ip_str)
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for network in BLOCKED_NETWORKS:
        if ip in network:
            # Networks are disjoint, so a private-range match cannot also be a
            # loopback/metadata match -- skipping it here safely allows only private IPs.
            if allow_private_ips and network in PRIVATE_NETWORKS:
                continue
            return True
    return False


def _parse_ip_literal(ip_str: str) -> object | None:
    """Parse an IP literal, tolerating the alternate numeric encodings (decimal 2130706433, hex
    0x7f000001, octal 0177.0.0.1, short forms) that inet_aton-based HTTP clients dial but
    ipaddress.ip_address REJECTS -- so a loopback/metadata literal in a non-canonical encoding is
    still classified as an IP (hence blockable) even without DNS. Returns None for a real hostname."""
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(ip_str))
    except (OSError, ValueError):
        return None


def is_host_blocked(hostname: str, allow_private_ips: bool = False) -> bool:
    """
    Check if a hostname is blocked.

    Args:
        hostname: Hostname to check
        allow_private_ips: If True, permit a direct private-range IP literal. The BLOCKED_HOSTS
            name list (localhost, cloud-metadata hostnames, ...) stays blocked regardless.

    Returns:
        True if blocked, False if allowed
    """
    if not hostname:
        return True

    hostname_lower = hostname.lower().strip('.')

    # Check exact match -- localhost / metadata hostnames stay blocked even with allow_private_ips.
    if hostname_lower in BLOCKED_HOSTS:
        return True

    # Check if it's a direct IP address
    if is_ip_blocked(hostname, allow_private_ips):
        return True

    return False


def resolve_and_validate_host(hostname: str, allow_private_ips: bool = False) -> bool:
    """
    Resolve hostname and validate the resulting IP is safe.

    This prevents DNS rebinding attacks by checking the resolved IP.

    Args:
        hostname: Hostname to resolve and validate

    Returns:
        True if safe, False if blocked
    """
    if is_host_blocked(hostname, allow_private_ips):
        return False

    try:
        # Try to parse as IP first
        ip = ipaddress.ip_address(hostname)
        return not is_ip_blocked(str(ip), allow_private_ips)
    except ValueError:
        pass

    # Resolve hostname
    try:
        results = socket.getaddrinfo(
            hostname, None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        if not results:
            return False

        for _family, _socktype, _proto, _canonname, sockaddr in results:
            ip_str = str(sockaddr[0])
            if is_ip_blocked(ip_str, allow_private_ips):
                logger.warning(
                    "ssrf_blocked_resolved_ip",
                    hostname=hostname,
                    resolved_ip=ip_str,
                )
                return False

        return True

    except socket.gaierror:
        # Cannot resolve - block unresolvable hosts
        return False


def is_url_safe(
    url: str,
    resolve_dns: bool = True,
    allow_private_ips: bool = False,
) -> tuple[bool, str]:
    """
    Check if a URL is safe to request (SSRF protection).

    Args:
        url: URL to validate
        resolve_dns: Whether to resolve and validate DNS
        allow_private_ips: Opt-in for authorized internal scanning -- permit RFC1918/CGNAT/ULA
            private ranges while keeping loopback / link-local (cloud metadata) / multicast /
            reserved and the blocked-hostname list (localhost, ...) blocked.

    Returns:
        Tuple of (is_safe, reason)
    """
    if not url:
        return False, "Empty URL"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL: {e}"

    # Check scheme
    scheme = (parsed.scheme or '').lower()
    if scheme in BLOCKED_SCHEMES:
        return False, f"Blocked scheme: {scheme}"

    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme: {scheme}"

    # Check hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    if is_host_blocked(hostname, allow_private_ips):
        return False, f"Blocked host: {hostname}"

    # Optionally resolve and validate DNS
    if resolve_dns:
        if not resolve_and_validate_host(hostname, allow_private_ips):
            return False, f"Resolved IP is blocked for: {hostname}"

    return True, "OK"


def ssrf_block_hint(reason: str) -> str:
    """Map an is_url_safe() block reason to an actionable remedy shown next to the warning.

    Honest and conditional: a resolved private IP CAN be scanned with --allow-private-ips (for an
    authorized internal target), but loopback / cloud-metadata / non-http schemes stay blocked by
    design, so those never recommend the flag."""
    r = (reason or "").lower()
    if "resolved ip is blocked" in r:
        return ("if this is an AUTHORIZED internal/dev target on a private network, re-run with "
                "--allow-private-ips (loopback & cloud-metadata stay blocked regardless)")
    if "blocked host" in r:
        return "localhost / cloud-metadata hostnames are blocked by design and cannot be scanned"
    if "scheme" in r:
        return "only http:// and https:// URLs are scanned"
    if "hostname" in r or "empty url" in r or "invalid url" in r:
        return "check the URL -- missing or invalid hostname"
    return "verify the target is authorized and reachable"


def sanitize_url(url: str) -> str | None:
    """
    Sanitize and validate a URL.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL or None if invalid/blocked
    """
    is_safe, reason = is_url_safe(url, resolve_dns=False)

    if not is_safe:
        logger.warning("url_blocked", url=url[:100], reason=reason, hint=ssrf_block_hint(reason))
        return None

    return url


# =============================================================================
# Path Traversal Protection
# =============================================================================

def is_path_safe(
    path: Path,
    allowed_bases: list[Path],
    allow_symlinks: bool = False,
) -> tuple[bool, str]:
    """
    Check if a path is safe (no traversal outside allowed directories).

    Args:
        path: Path to validate
        allowed_bases: List of allowed base directories
        allow_symlinks: Whether to allow symlinks

    Returns:
        Tuple of (is_safe, reason)
    """
    if not allowed_bases:
        return False, "No allowed base directories specified"

    try:
        # Resolve to absolute path
        if allow_symlinks:
            # Collapse '..'/'.' LEXICALLY (without following symlinks) -- path.absolute() alone
            # PRESERVES '..', and is_relative_to compares parts positionally, so a traversal like
            # `base/../../etc/passwd` would read as "inside base". normpath closes that hole while
            # still not resolving symlinks (the point of allow_symlinks).
            resolved = Path(os.path.normpath(str(path.absolute())))
        else:
            resolved = path.resolve()  # Resolves symlinks

        # Check if resolved path is within any allowed base
        for base in allowed_bases:
            try:
                base_resolved = (
                    base.resolve() if not allow_symlinks
                    else Path(os.path.normpath(str(base.absolute())))
                )

                # Normalize case/separators so containment holds on Windows, where
                # paths are case-insensitive and .absolute() does not canonicalize
                # case (e.g. "c:\proj\app.js" vs base "C:\Proj"). No-op on POSIX.
                resolved_cmp = Path(os.path.normcase(str(resolved)))
                base_cmp = Path(os.path.normcase(str(base_resolved)))

                # Use is_relative_to (Python 3.9+)
                if resolved_cmp.is_relative_to(base_cmp):
                    return True, "OK"

            except (ValueError, OSError):
                continue

        return False, f"Path {resolved} is outside allowed directories"

    except (ValueError, OSError) as e:
        return False, f"Invalid path: {e}"


def sanitize_path(
    path: str | Path,
    allowed_bases: list[Path],
    allow_symlinks: bool = False,
) -> Path | None:
    """
    Sanitize and validate a file path.

    Args:
        path: Path to sanitize
        allowed_bases: List of allowed base directories
        allow_symlinks: Whether to allow symlinks

    Returns:
        Sanitized Path or None if invalid/blocked
    """
    path = Path(path)

    is_safe, reason = is_path_safe(path, allowed_bases, allow_symlinks)

    if not is_safe:
        logger.warning(
            "path_blocked",
            path=str(path),
            reason=reason,
        )
        return None

    return path.resolve()


# =============================================================================
# Input Sanitization
# =============================================================================

# Maximum lengths for various inputs
MAX_URL_LENGTH = 2048
MAX_PATH_LENGTH = 4096
MAX_PATTERN_LENGTH = 256


def sanitize_string_input(
    value: str,
    max_length: int = 1000,
    allow_newlines: bool = False,
) -> str:
    """
    Sanitize a string input.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to allow newline characters

    Returns:
        Sanitized string
    """
    if not value:
        return ""

    # Truncate to max length
    value = value[:max_length]

    # Remove null bytes
    value = value.replace('\x00', '')

    # Optionally remove newlines
    if not allow_newlines:
        value = value.replace('\n', ' ').replace('\r', ' ')

    return value


def mask_sensitive_value(
    value: str,
    visible_start: int = 4,
    visible_end: int = 4,
    mask_char: str = '*',
) -> str:
    """
    Mask a sensitive value for safe logging/display.

    Args:
        value: Value to mask
        visible_start: Number of characters to show at start
        visible_end: Number of characters to show at end
        mask_char: Character to use for masking

    Returns:
        Masked value
    """
    if not value:
        return ""

    length = len(value)
    visible_start = max(0, visible_start)
    visible_end = max(0, visible_end)

    if length <= visible_start + visible_end:
        return mask_char * length

    # Never reveal more than a quarter of the characters per side: with a fixed 4+4 window a value
    # just over the threshold (e.g. 9 chars) would otherwise expose almost the whole secret
    # ('hunter2!!' -> 'hunt*r2!!', 8 of 9). Clamping keeps masking dominant for short values while
    # long secrets (>=16 chars) still show the full first/last window.
    cap = length // 4
    visible_start = min(visible_start, cap)
    visible_end = min(visible_end, cap)

    masked_length = length - visible_start - visible_end
    end_part = value[-visible_end:] if visible_end > 0 else ""
    return (
        value[:visible_start] +
        mask_char * masked_length +
        end_part
    )
