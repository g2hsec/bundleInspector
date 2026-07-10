"""
Internal domain detector.

Detects internal domains, IPs, and infrastructure hints.
"""

from __future__ import annotations

import re
from typing import Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)


class DomainDetector(BaseRule):
    """
    Detect internal domains and infrastructure references.

    Looks for:
    - Internal domain patterns (*.internal, *.local, staging.*, dev.*)
    - Private IP addresses
    - Cloud storage buckets (S3, GCS)
    - Internal service discovery URLs
    """

    id = "domain-detector"
    name = "Internal Domain Detector"
    description = "Detects internal domains and infrastructure references"
    category = Category.DOMAIN
    severity = Severity.MEDIUM

    # Internal domain patterns
    INTERNAL_PATTERNS = [
        # Environment prefixes
        (r"\b(?:dev|development|staging|stg|stage|test|qa|uat|preprod|pre-prod|sandbox)[-.]", "staging_domain"),
        (r"[-.](?:dev|development|staging|stg|stage|test|qa|uat|preprod|pre-prod|sandbox)\.", "staging_domain"),

        # Cloud metadata host (SSRF/IMDS) -- specific, before the broad `.internal` suffix
        (r"\bmetadata\.google\.internal\b", "gcp_metadata_host"),

        # Internal suffixes
        (r"\.(?:internal|local|localhost|corp|intranet|private|lan)\b", "internal_domain"),

        # Kubernetes/container patterns
        (r"\.(?:svc\.cluster\.local|pod\.cluster\.local)", "k8s_service"),
        (r"(?:kubernetes|k8s)[-.]", "k8s_reference"),

        # AWS internal
        (r"\.(?:compute\.internal|ec2\.internal)", "aws_internal"),
        (r"\.(?:amazonaws\.com/internal|aws\.internal)", "aws_internal"),

        # Docker
        (r"(?:docker|container)[-.](?:host|internal)", "docker_internal"),
    ]

    # Private IP patterns
    PRIVATE_IP_PATTERNS = [
        # Cloud metadata (IMDS) -- the single highest-signal SSRF target. SPECIFIC before the broad
        # 169.254.0.0/16 link-local so the loop `break` dedups to one finding for 169.254.169.254.
        (r"\b169\.254\.169\.254\b", "cloud_metadata_ip"),
        # 169.254.0.0/16 link-local (also the base for GCP/Azure IMDS reachability)
        (r"\b169\.254\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b", "link_local_ip"),
        # 10.0.0.0/8
        (r"\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b", "private_ip_10"),
        # 172.16.0.0/12
        (r"\b172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b", "private_ip_172"),
        # 192.168.0.0/16
        (r"\b192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b", "private_ip_192"),
        # 127.0.0.0/8 (loopback)
        (r"\b127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b", "loopback_ip"),
    ]

    # Cloud storage patterns
    CLOUD_STORAGE_PATTERNS = [
        # AWS S3
        # Bounded quantifiers ({1,253}/{1,63}) keep this linear: the unbounded `[a-z0-9.-]+`
        # before `.s3.` overlapped the following literal and backtracked O(n^2) on long dotted
        # literals. A real hostname is <=253 chars, so the match set is unchanged.
        (r"(?:https?://)?([a-z0-9.-]{1,253})\.s3\.(?:[a-z0-9-]{1,63}\.)?amazonaws\.com", "s3_bucket"),
        (r"(?:https?://)?s3\.(?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9.-]+)", "s3_bucket"),
        (r"s3://([a-z0-9.-]+)", "s3_bucket"),

        # GCS
        (r"(?:https?://)?storage\.googleapis\.com/([a-z0-9._-]+)", "gcs_bucket"),
        (r"gs://([a-z0-9._-]+)", "gcs_bucket"),

        # Azure
        (r"(?:https?://)?([a-z0-9]+)\.blob\.core\.windows\.net", "azure_blob"),
    ]

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match internal domains in IR."""
        seen_values = set()

        for literal in ir.string_literals:
            value = literal.value

            # Skip short strings
            if len(value) < 5:
                continue

            # Skip duplicates
            if value in seen_values:
                continue
            seen_values.add(value)

            # Check internal domain patterns
            for pattern, domain_type in self.INTERNAL_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    # Extract domain
                    domain = self._extract_domain(value)

                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Internal Domain: {domain_type.replace('_', ' ').title()}",
                        description=f"Found reference to internal/staging domain: {domain}",
                        extracted_value=domain or value,
                        value_type=domain_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        tags=["domain", domain_type],
                    )
                    break

            # Check private IPs
            for pattern, ip_type in self.PRIVATE_IP_PATTERNS:
                match = re.search(pattern, value)
                if match:
                    ip = match.group(0)

                    # Validate octets are <= 255
                    parts = ip.split(".")
                    if any(int(p) > 255 for p in parts):
                        continue

                    if ip_type == "cloud_metadata_ip":
                        sev = Severity.HIGH
                        title = "Cloud Metadata (IMDS) Endpoint"
                        desc = (f"Reference to the cloud instance-metadata service {ip} -- a prime "
                                f"SSRF target (steals IAM/instance credentials).")
                        tags = ["ip", "ssrf", "cloud-metadata"]
                    elif ip_type == "link_local_ip":
                        sev = Severity.MEDIUM
                        title = "Link-Local Address"
                        desc = f"Reference to a link-local address {ip} (169.254.0.0/16) -- SSRF/IMDS reachable."
                        tags = ["ip", "link-local"]
                    else:
                        sev = Severity.LOW if ip_type == "loopback_ip" else Severity.MEDIUM
                        title = "Private IP Address"
                        desc = f"Found private IP address: {ip}"
                        tags = ["ip", "private"]
                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=sev,
                        confidence=Confidence.HIGH,
                        title=title,
                        description=desc,
                        extracted_value=ip,
                        value_type=ip_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        tags=tags,
                    )
                    break

            # Check cloud storage
            for pattern, storage_type in self.CLOUD_STORAGE_PATTERNS:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    bucket = match.group(1) if match.groups() else match.group(0)

                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Cloud Storage: {storage_type.replace('_', ' ').upper()}",
                        description=f"Found cloud storage reference: {bucket}",
                        extracted_value=value,
                        value_type=storage_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        tags=["cloud", storage_type],
                        metadata={"bucket": bucket},
                    )
                    break

    def _extract_domain(self, value: str) -> str:
        """Extract domain from URL or string."""
        # Try to extract domain from URL
        match = re.search(
            r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            value
        )
        if match:
            return match.group(1)

        return value

