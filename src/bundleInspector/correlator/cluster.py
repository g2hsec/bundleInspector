"""
Cluster builder for grouping related findings.
"""

from __future__ import annotations

import re
from collections import defaultdict
from ipaddress import AddressValueError, IPv6Address
from urllib.parse import unquote

from bundleInspector.core.url_utils import safe_urlparse as urlparse
from bundleInspector.storage.models import Category, Cluster, Finding


def canonicalize_origin(value: str) -> str:
    """Return a credential-free canonical HTTP(S) origin, or an empty string.

    Hostname case and default ports are not origin distinctions. Userinfo is deliberately omitted
    from both grouping keys and cluster IDs so credentials cannot fragment or leak through reports.
    """
    if not value.lower().startswith(("http://", "https://", "//")):
        return ""
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"", "http", "https"} or not parsed.netloc:
        return ""
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return ""
    if not hostname:
        return ""

    hostname = hostname.rstrip(".")
    if not hostname:
        return ""
    if ":" in hostname:
        address, zone_marker, zone = hostname.partition("%")
        try:
            normalized_address = IPv6Address(address).compressed
        except AddressValueError:
            return ""
        zone_suffix = f"%{zone}" if zone_marker and zone else ""
        rendered_host = f"[{normalized_address}{zone_suffix}]"
    else:
        try:
            rendered_host = hostname.lower().encode("idna").decode("ascii")
        except UnicodeError:
            return ""

    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    return f"{scheme}://{authority}" if scheme else f"//{authority}"


class ClusterBuilder:
    """
    Build clusters of related findings.

    Groups findings by common characteristics like:
    - Base URL
    - API prefix
    - Authentication pattern
    - Functionality area
    """

    def __init__(self) -> None:
        self._clusters: dict[str, Cluster] = {}

    def build(self, findings: list[Finding]) -> list[Cluster]:
        """
        Build clusters from findings.

        Args:
            findings: List of findings to cluster

        Returns:
            List of clusters
        """
        self._clusters.clear()
        findings = sorted(
            findings,
            key=lambda finding: (
                finding.evidence.file_url,
                finding.evidence.line,
                finding.evidence.column,
                finding.id,
            ),
        )

        # Group by base URL
        self._cluster_by_base_url(findings)

        # Group by API prefix
        self._cluster_by_prefix(findings)

        # Group by functionality
        self._cluster_by_functionality(findings)

        return list(self._clusters.values())

    def _cluster_by_base_url(self, findings: list[Finding]) -> None:
        """Cluster findings by base URL."""
        url_groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category == Category.ENDPOINT:
                base_url = self._extract_base_url(finding.extracted_value)
                if base_url:
                    url_groups[base_url].append(finding)

        for base_url in sorted(url_groups):
            grouped = url_groups[base_url]
            if len(grouped) >= 2:
                cluster_id = f"base_url:{base_url}"
                self._clusters[cluster_id] = Cluster(
                    id=cluster_id,
                    name=f"API: {base_url}",
                    description=f"Endpoints sharing base URL: {base_url}",
                    finding_ids=[f.id for f in grouped],
                    common_traits={"base_url": base_url, "type": "base_url"},
                )

    def _cluster_by_prefix(self, findings: list[Finding]) -> None:
        """Cluster findings by API prefix."""
        prefix_groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category == Category.ENDPOINT:
                prefix = self._extract_prefix(finding.extracted_value)
                if prefix:
                    prefix_groups[prefix].append(finding)

        for prefix in sorted(prefix_groups):
            grouped = prefix_groups[prefix]
            if len(grouped) >= 2:
                cluster_id = f"prefix:{prefix}"
                if cluster_id not in self._clusters:
                    self._clusters[cluster_id] = Cluster(
                        id=cluster_id,
                        name=f"API Prefix: {prefix}",
                        description=f"Endpoints with prefix: {prefix}",
                        finding_ids=[f.id for f in grouped],
                        common_traits={"prefix": prefix, "type": "prefix"},
                    )

    def _cluster_by_functionality(self, findings: list[Finding]) -> None:
        """Cluster findings by functionality area."""
        func_keywords = {
            "auth": frozenset(
                {
                    "auth",
                    "authenticate",
                    "authentication",
                    "authorization",
                    "login",
                    "logout",
                    "oauth",
                    "session",
                    "sessions",
                    "token",
                    "tokens",
                }
            ),
            "user": frozenset(
                {"user", "users", "profile", "profiles", "account", "accounts", "member", "members"}
            ),
            "admin": frozenset(
                {"admin", "admins", "manage", "management", "dashboard", "internal"}
            ),
            "payment": frozenset(
                {"payment", "payments", "checkout", "billing", "subscription", "subscriptions", "stripe"}
            ),
            "upload": frozenset(
                {"upload", "uploads", "file", "files", "media", "image", "images", "attachment", "attachments"}
            ),
            "notification": frozenset(
                {"notification", "notifications", "email", "emails", "sms", "push", "alert", "alerts"}
            ),
            "api": frozenset({"graphql", "rest", "rpc"}),
        }

        func_groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category != Category.ENDPOINT:
                continue
            value_tokens = self._functionality_tokens(finding.extracted_value)

            for func, keywords in func_keywords.items():
                if value_tokens.intersection(keywords):
                    func_groups[func].append(finding)
                    break

        for func in sorted(func_groups):
            grouped = func_groups[func]
            if len(grouped) >= 2:
                cluster_id = f"func:{func}"
                if cluster_id not in self._clusters:
                    self._clusters[cluster_id] = Cluster(
                        id=cluster_id,
                        name=f"Functionality: {func.title()}",
                        description=f"Findings related to {func} functionality",
                        finding_ids=[f.id for f in grouped],
                        common_traits={"functionality": func, "type": "functionality"},
                    )

    def _extract_base_url(self, value: str) -> str:
        """Extract base URL from endpoint."""
        return canonicalize_origin(value)

    @staticmethod
    def _functionality_tokens(value: str) -> set[str]:
        """Tokenize endpoint path/query/fragment without matching arbitrary substrings."""
        parsed = urlparse(value) if value.lower().startswith(("http://", "https://", "//")) else None
        semantic_value = (
            " ".join((parsed.path, parsed.query, parsed.fragment)) if parsed is not None else value
        )
        decoded = unquote(semantic_value)
        camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", decoded)
        return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", camel_split)}

    def _extract_prefix(self, value: str) -> str:
        """Extract API prefix from path."""
        # Strip domain from full URLs to get just the path
        if value.lower().startswith(("http://", "https://", "//")):
            parsed = urlparse(value)
            value = parsed.path or "/"

        # Match common API prefixes
        match = re.match(r"^(/(?:api|v\d+|rest|graphql)[^/]*)", value)
        if match:
            return match.group(1)

        # Match first path segment
        match = re.match(r"^(/[a-zA-Z0-9_-]+)", value)
        if match:
            return match.group(1)

        return ""
