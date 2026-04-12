
"""
Cluster builder for grouping related findings.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from bundleInspector.storage.models import Category, Cluster, Finding


class ClusterBuilder:
    """
    Build clusters of related findings.

    Groups findings by common characteristics like:
    - Base URL
    - API prefix
    - Authentication pattern
    - Functionality area
    """

    def __init__(self):
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

        for base_url, grouped in url_groups.items():
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

        for prefix, grouped in prefix_groups.items():
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
            "auth": ["auth", "login", "logout", "session", "token", "oauth"],
            "user": ["user", "profile", "account", "member"],
            "admin": ["admin", "manage", "dashboard", "internal"],
            "payment": ["payment", "checkout", "billing", "subscription", "stripe"],
            "upload": ["upload", "file", "media", "image", "attachment"],
            "notification": ["notification", "email", "sms", "push", "alert"],
            "api": ["graphql", "rest", "rpc"],  # Last; removed generic "api"
        }

        func_groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category != Category.ENDPOINT:
                continue
            value_lower = finding.extracted_value.lower()

            for func, keywords in func_keywords.items():
                if any(kw in value_lower for kw in keywords):
                    func_groups[func].append(finding)
                    break

        for func, grouped in func_groups.items():
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
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            return f"{parsed.scheme}://{parsed.netloc}"
        elif value.startswith("//"):
            parsed = urlparse(value)
            return f"//{parsed.netloc}" if parsed.netloc else ""
        return ""

    def _extract_prefix(self, value: str) -> str:
        """Extract API prefix from path."""
        import re

        # Strip domain from full URLs to get just the path
        if value.startswith(("http://", "https://", "//")):
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

