"""
Security utilities for BundleInspector.

Provides protection against SSRF, path traversal, and other attacks.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from typing import Optional
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

# Dangerous URL schemes
BLOCKED_SCHEMES = frozenset({
    'javascript', 'data', 'vbscript', 'file',
    'ftp', 'gopher', 'ldap', 'dict', 'sftp',
})

# Allowed URL schemes
ALLOWED_SCHEMES = frozenset({'http', 'https'})


def is_ip_blocked(ip_str: str) -> bool:
    """
    Check if an IP address is in a blocked network.

    Args:
        ip_str: IP address string

    Returns:
        True if blocked, False if allowed
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_host_blocked(hostname: str) -> bool:
    """
    Check if a hostname is blocked.

    Args:
        hostname: Hostname to check

    Returns:
        True if blocked, False if allowed
    """
    if not hostname:
        return True

    hostname_lower = hostname.lower().strip('.')

    # Check exact match
    if hostname_lower in BLOCKED_HOSTS:
        return True

    # Check if it's a direct IP address
    if is_ip_blocked(hostname):
        return True

    return False


def resolve_and_validate_host(hostname: str) -> bool:
    """
    Resolve hostname and validate the resulting IP is safe.

    This prevents DNS rebinding attacks by checking the resolved IP.

    Args:
        hostname: Hostname to resolve and validate

    Returns:
        True if safe, False if blocked
    """
    if is_host_blocked(hostname):
        return False

    try:
        # Try to parse as IP first
        ip = ipaddress.ip_address(hostname)
        return not is_ip_blocked(str(ip))
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

        for family, socktype, proto, canonname, sockaddr in results:
            ip_str = sockaddr[0]
            if is_ip_blocked(ip_str):
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


def is_url_safe(url: str, resolve_dns: bool = True) -> tuple[bool, str]:
    """
    Check if a URL is safe to request (SSRF protection).

    Args:
        url: URL to validate
        resolve_dns: Whether to resolve and validate DNS

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

    if is_host_blocked(hostname):
        return False, f"Blocked host: {hostname}"

    # Optionally resolve and validate DNS
    if resolve_dns:
        if not resolve_and_validate_host(hostname):
            return False, f"Resolved IP is blocked for: {hostname}"

    return True, "OK"


def sanitize_url(url: str) -> Optional[str]:
    """
    Sanitize and validate a URL.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL or None if invalid/blocked
    """
    is_safe, reason = is_url_safe(url, resolve_dns=False)

    if not is_safe:
        logger.warning("url_blocked", url=url[:100], reason=reason)
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
            resolved = path.absolute()
        else:
            resolved = path.resolve()  # Resolves symlinks

        # Check if resolved path is within any allowed base
        for base in allowed_bases:
            try:
                base_resolved = base.resolve() if not allow_symlinks else base.absolute()

                # Use is_relative_to (Python 3.9+)
                if resolved.is_relative_to(base_resolved):
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
) -> Optional[Path]:
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

    if length <= visible_start + visible_end:
        return mask_char * length

    masked_length = length - visible_start - visible_end
    end_part = value[-visible_end:] if visible_end > 0 else ""
    return (
        value[:visible_start] +
        mask_char * masked_length +
        end_part
    )

