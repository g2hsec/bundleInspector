"""
Internal domain detector.

Detects internal domains, IPs, and infrastructure hints.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

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
        (
            r"\b(?:dev|development|staging|stg|stage|test|qa|uat|preprod|pre-prod|sandbox)[-.]",
            "staging_domain",
        ),
        (
            r"[-.](?:dev|development|staging|stg|stage|test|qa|uat|preprod|pre-prod|sandbox)\.",
            "staging_domain",
        ),
        # Cloud metadata host (SSRF/IMDS) -- specific, before the broad `.internal` suffix
        (r"\bmetadata\.google\.internal\b", "gcp_metadata_host"),
        # Kubernetes/container patterns
        (r"\.(?:svc\.cluster\.local|pod\.cluster\.local)", "k8s_service"),
        (r"(?:kubernetes|k8s)[-.]", "k8s_reference"),
        # AWS internal
        (r"\.(?:compute\.internal|ec2\.internal)", "aws_internal"),
        (r"\.(?:amazonaws\.com/internal|aws\.internal)", "aws_internal"),
        # Internal suffixes (generic, after provider-specific forms)
        (r"\.(?:internal|local|localhost|corp|intranet|private|lan)\b", "internal_domain"),
        # Docker
        (r"(?:docker|container)[-.](?:host|internal)", "docker_internal"),
    ]

    # File extensions that mark a value as a filename/asset, not a hostname (DQ-D03).
    _NON_DOMAIN_EXTS = (
        ".csv",
        ".json",
        ".md",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".html",
        ".css",
        ".scss",
        ".less",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".txt",
        ".yml",
        ".yaml",
        ".map",
        ".xml",
        ".pdf",
        ".zip",
        ".woff",
        ".woff2",
        ".ttf",
        ".ico",
    )

    def _looks_like_non_domain(self, value: str) -> bool:
        """True when the value is a filename/identifier rather than a hostname (DQ-D03).

        The file-extension check applies to the extracted HOST only, NOT the whole URL path -- a real
        internal/staging host whose PATH ends in an asset extension (https://staging.example.com/main.js)
        must still be reported. A host ends in a TLD, never a file extension; a bare token with no
        dotted host is not a domain."""
        v = value.strip()
        if "://" in v:
            v = v.split("://", 1)[1]
        elif v.startswith("//"):
            v = v[2:]
        host = v.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip().lower()
        if not host or "." not in host:
            return True  # bare token / identifier, not a dotted host
        return host.endswith(self._NON_DOMAIN_EXTS)  # host ending in a FILE extension is a filename

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
        (
            r"(?:https?://)?([a-z0-9.-]{1,253})\.s3\.(?:[a-z0-9-]{1,63}\.)?amazonaws\.com",
            "s3_bucket",
        ),
        (r"(?:https?://)?s3\.(?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9.-]+)", "s3_bucket"),
        (r"s3://([a-z0-9.-]+)", "s3_bucket"),
        # GCS
        (r"(?:https?://)?storage\.googleapis\.com/([a-z0-9._-]+)", "gcs_bucket"),
        (r"gs://([a-z0-9._-]+)", "gcs_bucket"),
        # Azure
        # Bounded ({1,63}) for the same ReDoS reason as the S3 pattern: the unbounded `[a-z0-9]+`
        # before `.blob.` backtracked O(n^2) on a long alnum literal. Storage account names are
        # <=24 chars (DNS label <=63), so the match set is unchanged.
        (r"(?:https?://)?([a-z0-9]{1,63})\.blob\.core\.windows\.net", "azure_blob"),
    ]

    _HOST_CANDIDATE = re.compile(
        r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z][A-Za-z0-9_-]{1,62}(?![A-Za-z0-9_-])"
    )

    def _iter_hosts(self, value: str) -> Iterator[tuple[str, int]]:
        seen: set[str] = set()
        for match in self._HOST_CANDIDATE.finditer(value):
            host = match.group(0).lower().rstrip(".")
            if host in seen or self._looks_like_non_domain(host):
                continue
            seen.add(host)
            yield host, match.start()

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match internal domains in IR."""
        seen_values: set[tuple[object, ...]] = set()

        for literal in ir.string_literals:
            value = literal.value

            # Skip short strings
            if len(value) < 5:
                continue

            # Check internal domain patterns
            for domain, offset in self._iter_hosts(value):
                for pattern, domain_type in self.INTERNAL_PATTERNS:
                    if not re.search(pattern, domain, re.IGNORECASE):
                        continue
                    sig: tuple[object, ...] = ("domain", domain, domain_type, literal.line)
                    if sig in seen_values:
                        break
                    seen_values.add(sig)
                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Internal Domain: {domain_type.replace('_', ' ').title()}",
                        description=f"Found reference to internal/staging domain: {domain}",
                        extracted_value=domain,
                        value_type=domain_type,
                        line=literal.line,
                        column=literal.column + offset,
                        ast_node_type="Literal",
                        tags=["domain", domain_type],
                    )
                    break

            # Check private IPs
            for pattern, ip_type in self.PRIVATE_IP_PATTERNS:
                for match in re.finditer(pattern, value):
                    ip = match.group(0)

                    # A dotted numeric token surrounding the match means this is a sub-IP of an
                    # invalid larger value (e.g. 999.10.0.0.1), not a standalone address.
                    if (match.start() > 0 and value[match.start() - 1] in ".0123456789") or (
                        match.end() < len(value) and value[match.end()] in ".0123456789"
                    ):
                        continue

                    # Validate octets are <= 255
                    parts = ip.split(".")
                    if any(int(p) > 255 for p in parts):
                        continue
                    sig = ("ip", ip, literal.line)
                    if sig in seen_values:
                        continue
                    seen_values.add(sig)

                    if ip_type == "cloud_metadata_ip":
                        sev = Severity.HIGH
                        title = "Cloud Metadata (IMDS) Endpoint"
                        desc = (
                            f"Reference to the cloud instance-metadata service {ip} -- a prime "
                            f"SSRF target (steals IAM/instance credentials)."
                        )
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
                        column=literal.column + match.start(),
                        ast_node_type="Literal",
                        tags=tags,
                    )

            # Check cloud storage
            for pattern, storage_type in self.CLOUD_STORAGE_PATTERNS:
                for match in re.finditer(pattern, value, re.IGNORECASE):
                    bucket = match.group(1) if match.groups() else match.group(0)

                    sig = ("storage", storage_type, match.group(0), literal.line)
                    if sig in seen_values:
                        continue
                    seen_values.add(sig)

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
                        column=literal.column + match.start(),
                        ast_node_type="Literal",
                        tags=["cloud", storage_type],
                        metadata={"bucket": bucket},
                    )

    def _extract_domain(self, value: str) -> str:
        """Extract domain from URL or string."""
        # Try to extract domain from URL. Bounded quantifiers ({1,253}/{2,63}) keep this linear --
        # the unbounded `[a-zA-Z0-9.-]+` overlapped the following `.[a-zA-Z]{2,}` literal and
        # backtracked O(n^2) on a long dotted/alnum literal with no letter-TLD (same ReDoS class the
        # S3 CLOUD_STORAGE pattern was already bounded for). A hostname is <=253 chars, a DNS/TLD
        # label <=63, so the match set is unchanged for real domains.
        match = re.search(r"(?:https?://)?([a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63})", value)
        if match:
            return match.group(1)

        return value
