"""Explicit allowlist projection for public/API/MCP report access."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from collections import deque
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from bundleInspector.reporter.redaction import REDACTED, redact_text, sanitize_uri
from bundleInspector.storage.models import (
    Category,
    Cluster,
    Correlation,
    Finding,
    JSAsset,
    Report,
    RiskTier,
    Severity,
)

PublicPageKind = Literal["findings", "assets", "correlations", "clusters"]
_MAX_HEADER_ITEMS = 100
_MAX_CLUSTER_FINDING_IDS = 100
_MAX_CURSOR_LENGTH = 4096
_MAX_PUBLIC_SCALAR_INPUT = 65_536
_MAX_PUBLIC_COUNTER = (1 << 63) - 1
_PUBLIC_ISSUE_CODES = frozenset({
    "analysis_exception",
    "asset_analysis_failed",
    "asset_analysis_incomplete",
    "browser_response_too_large",
    "correlation_graph_truncated",
    "crawl_terminal_failure",
    "crawl_transient_failure",
    "crawl_url_blocked",
    "custom_rule_analysis_incomplete",
    "degraded_parse",
    "dependency_frontier_guard",
    "dependency_frontier_ir_failed",
    "dependency_frontier_truncated",
    "download_http_rejected",
    "download_policy_skip",
    "download_transient_failure",
    "finding_enrichment_failed",
    "headless_crawl_failed",
    "ir_truncated",
    "local_component_malformed",
    "local_component_truncated",
    "local_component_unsupported",
    "local_diagnostic_cap",
    "local_file_oversized",
    "local_file_unreadable",
    "local_path_blocked",
    "local_sourcemap_blocked",
    "local_sourcemap_missing",
    "local_sourcemap_oversized",
    "local_sourcemap_unreadable",
    "max_js_files_reached",
    "navigation_policy_blocked",
    "normalization_exception",
    "normalization_failed",
    "parallel_worker_timeout",
    "parse_exception",
    "parse_failed",
    "parse_incomplete",
    "rule_analysis_incomplete",
    "sourcemap_mapping_truncated",
    "sourcemap_provenance_bases_truncated",
    "sourcemap_provenance_resolution_failed",
    "sourcemap_resolution_failed",
    "sourcemap_supplemental_sources_truncated",
    "virtual_source_analysis_incomplete",
})
_PUBLIC_ISSUE_STAGES = frozenset({
    "analyze",
    "classify",
    "collect",
    "complete",
    "correlate",
    "crawl",
    "download",
    "init",
    "normalize",
    "parse",
    "report",
    "resume",
})
_PUBLIC_NUMERIC_DETAIL_KEYS = frozenset({
    "affected_count",
    "analyzed_bytes",
    "analyzed_count",
    "attempts",
    "base_cap",
    "base_count",
    "byte_cap",
    "candidate_count",
    "depth_cap_hit",
    "discovered",
    "error_count",
    "event_cap",
    "exception_cap_hit",
    "http_status",
    "limit",
    "loop_cap_hit",
    "max_call_depth",
    "max_depth",
    "max_exception_states",
    "max_loop_iterations",
    "max_work",
    "occurrence_cap",
    "occurrence_count",
    "partial",
    "partial_results",
    "processed",
    "retained_bytes",
    "skipped_count",
    "source_cap",
    "source_count",
    "status",
    "timeout_seconds",
    "truncated_candidates",
    "truncated_candidates_lower_bound",
    "virtual_source",
    "work",
    "work_cap_hit",
})
_PUBLIC_CAPPED_PASS_NAMES = frozenset({
    "_add_call_graph_edges",
    "_add_config_edges",
    "_add_dynamic_import_edges",
    "_add_execution_call_chain_edges",
    "_add_execution_chain_edges",
    "_add_execution_scope_call_chain_edges",
    "_add_import_call_chain_edges",
    "_add_import_chain_edges",
    "_add_import_edges",
    "_add_import_scope_call_chain_edges",
    "_add_initiator_chain_edges",
    "_add_initiator_execution_call_chain_edges",
    "_add_initiator_execution_scope_call_chain_edges",
    "_add_inter_module_call_edges",
    "_add_load_context_call_chain_edges",
    "_add_load_context_chain_edges",
    "_add_load_context_downstream_call_chain_edges",
    "_add_load_context_execution_call_chain_edges",
    "_add_load_context_execution_chain_edges",
    "_add_load_context_execution_scope_call_chain_edges",
    "_add_load_context_import_call_chain_edges",
    "_add_load_context_import_chain_edges",
    "_add_load_context_import_scope_call_chain_edges",
    "_add_load_context_initiator_call_chain_edges",
    "_add_load_context_initiator_scope_call_chain_edges",
    "_add_load_context_runtime_execution_call_graph_edges",
    "_add_load_context_runtime_execution_graph_edges",
    "_add_load_context_runtime_execution_scope_call_graph_edges",
    "_add_load_context_scope_call_chain_edges",
    "_add_runtime_downstream_call_chain_edges",
    "_add_runtime_edges",
    "_add_runtime_execution_call_graph_edges",
    "_add_runtime_execution_graph_edges",
    "_add_runtime_execution_scope_call_graph_edges",
    "_add_runtime_scope_call_chain_edges",
    "_add_same_file_edges",
    "_add_secret_endpoint_edges",
    "_add_taint_chain_edges",
    "_add_transitive_import_edges",
})


class _SecretReplacementIndex:
    """Immutable multi-pattern replacement index for one public projection."""

    __slots__ = ("_best_outputs", "_failures", "_masks", "_patterns", "_transitions")

    def __init__(self, replacements: tuple[tuple[str, str], ...]):
        self._patterns = tuple(raw for raw, _masked in replacements)
        transitions: list[dict[str, int]] = [{}]
        terminals: list[int | None] = [None]
        for pattern_index, pattern in enumerate(self._patterns):
            state = 0
            for character in pattern:
                next_state = transitions[state].get(character)
                if next_state is None:
                    next_state = len(transitions)
                    transitions[state][character] = next_state
                    transitions.append({})
                    terminals.append(None)
                state = next_state
            terminals[state] = pattern_index

        failures = [0] * len(transitions)
        best_outputs = terminals.copy()
        pending: deque[int] = deque()
        for child in transitions[0].values():
            pending.append(child)
        while pending:
            state = pending.popleft()
            for character, child in transitions[state].items():
                pending.append(child)
                fallback = failures[state]
                while fallback and character not in transitions[fallback]:
                    fallback = failures[fallback]
                failures[child] = transitions[fallback].get(character, 0)
                inherited = best_outputs[failures[child]]
                own = best_outputs[child]
                if inherited is not None and (own is None or inherited < own):
                    best_outputs[child] = inherited

        self._transitions = tuple(transitions)
        self._failures = tuple(failures)
        self._best_outputs = tuple(best_outputs)
        self._masks = tuple(
            self._safe_mask(masked)
            for _raw, masked in replacements
        )

    def _safe_mask(self, masked: str) -> str:
        if not self.contains(masked):
            return masked
        if not self.contains(REDACTED):
            return REDACTED
        return ""

    def _match_starts(self, value: str) -> dict[int, int]:
        matches: dict[int, int] = {}
        state = 0
        for end, character in enumerate(value):
            while state and character not in self._transitions[state]:
                state = self._failures[state]
            state = self._transitions[state].get(character, 0)
            pattern_index = self._best_outputs[state]
            if pattern_index is None:
                continue
            start = end - len(self._patterns[pattern_index]) + 1
            previous = matches.get(start)
            if previous is None or pattern_index < previous:
                matches[start] = pattern_index
        return matches

    def contains(self, value: str) -> bool:
        state = 0
        for character in value:
            while state and character not in self._transitions[state]:
                state = self._failures[state]
            state = self._transitions[state].get(character, 0)
            if self._best_outputs[state] is not None:
                return True
        return False

    def replace(self, value: str) -> str:
        matches = self._match_starts(value)
        if not matches:
            return value
        parts: list[str] = []
        cursor = 0
        while cursor < len(value):
            pattern_index = matches.get(cursor)
            if pattern_index is None:
                parts.append(value[cursor])
                cursor += 1
                continue
            parts.append(self._masks[pattern_index])
            cursor += len(self._patterns[pattern_index])
        result = "".join(parts)
        return "" if self.contains(result) else result


_SecretReplacements = tuple[tuple[str, str], ...] | _SecretReplacementIndex


def _replace_known_secrets(value: str, replacements: _SecretReplacements) -> str:
    if isinstance(replacements, _SecretReplacementIndex):
        return replacements.replace(value)
    for raw, masked in replacements:
        value = value.replace(raw, masked)
    return value


def opaque_public_id(
    signing_key: bytes,
    kind: str,
    raw_id: str,
    *,
    namespace: str = "",
) -> str:
    """Return a stable, non-reversible ID suitable for an untrusted public boundary."""
    payload = f"{kind}\0{namespace}\0{raw_id}".encode("utf-8", "replace")
    digest = hmac.new(signing_key, payload, hashlib.sha256).digest()[:18]
    token = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{kind}-{token}"


class PublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicCompletenessIssue(PublicModel):
    code: str
    stage: str
    message: str
    retryable: bool
    affected_count: int = Field(ge=0)
    details: dict[str, object] = Field(default_factory=dict)


class PublicCompleteness(PublicModel):
    status: str
    is_complete: bool
    retryable: bool
    issue_count: int = Field(ge=0)
    issues_truncated: bool
    issues: list[PublicCompletenessIssue] = Field(default_factory=list)


class PublicSummary(PublicModel):
    total_js_files: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    findings_by_tier: dict[str, int]
    total_correlations: int = Field(ge=0)
    total_clusters: int = Field(ge=0)


class PublicEvidence(PublicModel):
    uri: str
    line: int = Field(ge=0)
    column: int = Field(ge=0)
    end_line: int | None = Field(default=None, ge=0)
    end_column: int | None = Field(default=None, ge=0)
    original_uri: str | None = None
    original_line: int | None = Field(default=None, ge=0)
    original_column: int | None = Field(default=None, ge=0)


class PublicFinding(PublicModel):
    id: str
    rule_id: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str
    value_type: str
    masked_value: str
    risk_tier: str | None = None
    risk_score: float = Field(ge=0, allow_inf_nan=False)
    evidence: PublicEvidence
    tags: list[str]
    confirmed: bool = False
    likely_false_positive: bool = False
    third_party_file: str | None = None


class PublicAsset(PublicModel):
    id: str
    uri: str
    content_hash: str
    size: int = Field(ge=0)
    source: str
    is_first_party: bool
    status_code: int = Field(ge=0)
    parse_success: bool
    parse_error_count: int = Field(ge=0)


class PublicCorrelation(PublicModel):
    id: str
    edge_type: str
    source_finding_id: str
    target_finding_id: str
    confidence: str
    reasoning: str


class PublicCluster(PublicModel):
    id: str
    name: str
    description: str
    finding_count: int = Field(ge=0)
    finding_ids_truncated: bool
    finding_ids: list[str]


class PublicReportView(PublicModel):
    schema_version: int = 1
    report_id: str
    job_id: str
    revision: str
    created_at: datetime
    completed_at: datetime | None
    duration_seconds: float = Field(ge=0, allow_inf_nan=False)
    target_count: int = Field(ge=0)
    targets_truncated: bool
    targets: list[str]
    summary: PublicSummary
    completeness: PublicCompleteness
    page_kind: PublicPageKind
    page_total: int = Field(ge=0)
    page_offset: int = Field(ge=0)
    page_count: int = Field(ge=0)
    page_truncated: bool
    findings: list[PublicFinding] = Field(default_factory=list)
    assets: list[PublicAsset] = Field(default_factory=list)
    correlations: list[PublicCorrelation] = Field(default_factory=list)
    clusters: list[PublicCluster] = Field(default_factory=list)
    next_cursor: str | None = None


class CursorError(ValueError):
    """Raised for malformed, stale, or context-mismatched public cursors."""


class PublicReportProjector:
    """Build bounded public pages without exposing internal Pydantic models."""

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("public cursor signing key must be at least 32 bytes")
        self._signing_key = signing_key

    def revision(
        self,
        report: Report,
        *,
        replacements: _SecretReplacements | None = None,
    ) -> str:
        if replacements is None:
            replacements = self._secret_replacements(report)
        digest = hashlib.sha256(b"bundle-inspector-public-report-v2\0")
        self._hash_revision_record(
            digest,
            "header",
            self._header_payload(report, replacements),
        )
        self._hash_revision_record(digest, "findings-count", len(report.findings))
        for finding in report.findings:
            self._hash_revision_record(
                digest,
                "finding",
                self._finding_payload(report, finding, replacements),
            )
        self._hash_revision_record(digest, "assets-count", len(report.assets))
        for asset in report.assets:
            self._hash_revision_record(
                digest,
                "asset",
                self._asset_payload(report, asset, replacements),
            )
        self._hash_revision_record(digest, "correlations-count", len(report.correlations))
        for correlation in report.correlations:
            self._hash_revision_record(
                digest,
                "correlation",
                self._correlation_payload(report, correlation, replacements),
            )
        self._hash_revision_record(digest, "clusters-count", len(report.clusters))
        for cluster in report.clusters:
            self._hash_revision_record(
                digest,
                "cluster",
                self._cluster_payload(report, cluster, replacements),
            )
        return digest.hexdigest()[:24]

    @staticmethod
    def _hash_revision_record(digest: Any, label: str, value: object) -> None:
        encoded_label = label.encode("ascii")
        encoded_value = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(len(encoded_label).to_bytes(2, "big"))
        digest.update(encoded_label)
        digest.update(len(encoded_value).to_bytes(8, "big"))
        digest.update(encoded_value)

    def project(
        self,
        report: Report,
        *,
        page_kind: PublicPageKind = "findings",
        limit: int = 50,
        cursor: str | None = None,
        principal_id: str = "local",
    ) -> PublicReportView:
        if page_kind not in ("findings", "assets", "correlations", "clusters"):
            raise ValueError("page_kind is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be in [1, 100]")
        replacements = self._secret_replacements(report)
        header = self._header_payload(report, replacements)
        revision = self.revision(report, replacements=replacements)
        public_report_id = str(header["report_id"])
        principal_binding = self._id("principal", principal_id)
        offset = 0
        if cursor:
            state = self._decode_cursor(cursor)
            expected = {
                "report_id": public_report_id,
                "revision": revision,
                "page_kind": page_kind,
                "limit": limit,
                "principal": principal_binding,
            }
            if any(state.get(key) != value for key, value in expected.items()):
                raise CursorError("cursor does not match this report revision and request context")
            raw_offset = state.get("offset")
            if isinstance(raw_offset, bool) or not isinstance(raw_offset, int) or raw_offset < 0:
                raise CursorError("cursor offset is invalid")
            offset = raw_offset

        item_count = self._page_item_count(report, page_kind)
        if offset > item_count:
            raise CursorError("cursor offset is invalid")
        page_items = self._project_page(
            report,
            page_kind,
            offset,
            limit,
            replacements,
        )
        next_offset = offset + len(page_items)
        page_truncated = next_offset < item_count
        next_cursor = None
        if page_truncated:
            next_cursor = self._encode_cursor({
                "report_id": public_report_id,
                "revision": revision,
                "page_kind": page_kind,
                "limit": limit,
                "principal": principal_binding,
                "offset": next_offset,
            })

        payload: dict[str, object] = {
            "schema_version": header["schema_version"],
            "report_id": public_report_id,
            "job_id": header["job_id"],
            "revision": revision,
            "created_at": header["created_at"],
            "completed_at": header["completed_at"],
            "duration_seconds": header["duration_seconds"],
            "target_count": header["target_count"],
            "targets_truncated": header["targets_truncated"],
            "targets": header["targets"],
            "summary": header["summary"],
            "completeness": header["completeness"],
            "page_kind": page_kind,
            "page_total": item_count,
            "page_offset": offset,
            "page_count": len(page_items),
            "page_truncated": page_truncated,
            "next_cursor": next_cursor,
            page_kind: page_items,
        }
        return PublicReportView.model_validate(payload)

    def _header_payload(
        self,
        report: Report,
        replacements: _SecretReplacements = (),
    ) -> dict[str, object]:
        """Build only the bounded public header shared by every page."""
        targets = [
            self._public_uri(url, replacements=replacements)
            for url in report.seed_urls[:_MAX_HEADER_ITEMS]
        ]
        issues = [
            self._public_issue_payload(issue)
            for issue in report.completeness.issues[:_MAX_HEADER_ITEMS]
        ]
        public_status = report.completeness.status.value
        if public_status == "complete" and report.completeness.issues:
            public_status = "partial"
        completeness = {
            "status": public_status,
            "is_complete": public_status == "complete" and not report.completeness.issues,
            "retryable": bool(report.completeness.retryable),
            "issue_count": len(report.completeness.issues),
            "issues_truncated": len(report.completeness.issues) > len(issues),
            "issues": issues,
        }
        return {
            "schema_version": 1,
            "report_id": self._id("report", report.id),
            "job_id": self._id("job", report.job_id),
            "created_at": report.created_at.isoformat(),
            "completed_at": report.completed_at.isoformat() if report.completed_at else None,
            "duration_seconds": report.duration_seconds,
            "target_count": len(report.seed_urls),
            "targets_truncated": len(report.seed_urls) > len(targets),
            "targets": targets,
            "summary": self._summary_payload(report, replacements),
            "completeness": completeness,
        }

    @classmethod
    def _summary_payload(
        cls,
        report: Report,
        replacements: _SecretReplacements,
    ) -> dict[str, object]:
        def public_counts(counts: list[tuple[str, int]]) -> dict[str, int]:
            projected: dict[str, int] = {}
            for key, count in counts:
                public_key = cls._public_text(key, replacements, max_length=100)
                projected[public_key] = projected.get(public_key, 0) + count
            return projected

        severity_counts = {severity.value: 0 for severity in Severity}
        category_counts = {category.value: 0 for category in Category}
        tier_counts = {tier.value: 0 for tier in RiskTier}
        for finding in report.findings:
            severity_counts[finding.severity.value] += 1
            category_counts[finding.category.value] += 1
            if finding.risk_tier is not None:
                tier_counts[finding.risk_tier.value] += 1

        return {
            "total_js_files": len(report.assets),
            "total_findings": len(report.findings),
            "findings_by_severity": public_counts(list(severity_counts.items())),
            "findings_by_category": public_counts(list(category_counts.items())),
            "findings_by_tier": public_counts(list(tier_counts.items())),
            "total_correlations": len(report.correlations),
            "total_clusters": len(report.clusters),
        }

    @staticmethod
    def _page_item_count(report: Report, page_kind: PublicPageKind) -> int:
        if page_kind == "findings":
            return len(report.findings)
        if page_kind == "assets":
            return len(report.assets)
        if page_kind == "correlations":
            return len(report.correlations)
        return len(report.clusters)

    def _project_page(
        self,
        report: Report,
        page_kind: PublicPageKind,
        offset: int,
        limit: int,
        replacements: _SecretReplacements,
    ) -> list[PublicModel]:
        end = offset + limit
        models: list[PublicModel] = []
        if page_kind == "findings":
            for finding in report.findings[offset:end]:
                models.append(self._finding(report, finding, replacements))
        elif page_kind == "assets":
            for asset in report.assets[offset:end]:
                models.append(
                    PublicAsset.model_validate(
                        self._asset_payload(report, asset, replacements)
                    )
                )
        elif page_kind == "correlations":
            for correlation in report.correlations[offset:end]:
                models.append(
                    PublicCorrelation.model_validate(
                        self._correlation_payload(report, correlation, replacements)
                    )
                )
        else:
            for cluster in report.clusters[offset:end]:
                models.append(
                    PublicCluster.model_validate(
                        self._cluster_payload(report, cluster, replacements)
                    )
                )
        return models

    def _asset_payload(
        self,
        report: Report,
        item: JSAsset,
        replacements: _SecretReplacements = (),
    ) -> dict[str, object]:
        return {
            "id": self._id("asset", item.id, report.id),
            "uri": self._public_uri(item.url, replacements=replacements),
            "content_hash": self._id("content", item.content_hash, report.id),
            "size": item.size,
            "source": item.source.value,
            "is_first_party": item.is_first_party,
            "status_code": item.status_code,
            "parse_success": item.parse_success,
            "parse_error_count": len(item.parse_errors),
        }

    def _correlation_payload(
        self,
        report: Report,
        item: Correlation,
        replacements: _SecretReplacements = (),
    ) -> dict[str, object]:
        return {
            "id": self._id("correlation", item.id, report.id),
            "edge_type": item.edge_type.value,
            "source_finding_id": self._id("finding", item.source_finding_id, report.id),
            "target_finding_id": self._id("finding", item.target_finding_id, report.id),
            "confidence": item.confidence.value,
            "reasoning": self._public_text(item.reasoning, replacements, max_length=500),
        }

    def _cluster_payload(
        self,
        report: Report,
        item: Cluster,
        replacements: _SecretReplacements = (),
    ) -> dict[str, object]:
        return {
            "id": self._id("cluster", item.id, report.id),
            "name": self._public_text(item.name, replacements, max_length=200),
            "description": self._public_text(
                item.description,
                replacements,
                max_length=500,
            ),
            "finding_count": len(item.finding_ids),
            "finding_ids_truncated": len(item.finding_ids) > _MAX_CLUSTER_FINDING_IDS,
            "finding_ids": [
                self._id("finding", finding_id, report.id)
                for finding_id in item.finding_ids[:_MAX_CLUSTER_FINDING_IDS]
            ],
        }

    def _finding(
        self,
        report: Report,
        finding: Finding,
        replacements: _SecretReplacements = (),
    ) -> PublicFinding:
        return PublicFinding.model_validate(
            self._finding_payload(report, finding, replacements)
        )

    def _finding_payload(
        self,
        report: Report,
        finding: Finding,
        replacements: _SecretReplacements = (),
    ) -> dict[str, object]:
        evidence = finding.evidence
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        public_value = self._public_text(
            finding.masked_value or finding.extracted_value,
            replacements,
            max_length=300,
        )
        if finding.category.value == "endpoint":
            public_value = public_value.split("?", 1)[0].split("#", 1)[0]
        return {
            "id": self._id("finding", finding.id, report.id),
            "rule_id": self._public_text(finding.rule_id, replacements, max_length=150),
            "category": finding.category.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "title": self._public_text(finding.title, replacements, max_length=300),
            "description": self._public_text(
                finding.description,
                replacements,
                max_length=1000,
            ),
            "value_type": self._public_text(
                finding.value_type,
                replacements,
                max_length=100,
            ),
            "masked_value": public_value,
            "risk_tier": finding.risk_tier.value if finding.risk_tier else None,
            "risk_score": finding.risk_score,
            "evidence": {
                "uri": self._public_uri(
                    evidence.file_url,
                    replacements=replacements,
                ),
                "line": evidence.line,
                "column": evidence.column,
                "end_line": evidence.end_line,
                "end_column": evidence.end_column,
                "original_uri": (
                    self._public_uri(
                        evidence.original_file_url,
                        replacements=replacements,
                    )
                    if evidence.original_file_url else None
                ),
                "original_line": evidence.original_line,
                "original_column": evidence.original_column,
            },
            "tags": [
                self._public_text(tag, replacements, max_length=100)
                for tag in finding.tags[:50]
            ],
            "confirmed": bool(metadata.get("confirmed")),
            "likely_false_positive": bool(metadata.get("likely_fp")),
            "third_party_file": (
                self._public_uri(
                    str(metadata["third_party_file"]),
                    max_length=100,
                    replacements=replacements,
                )
                if metadata.get("third_party_file") else None
            ),
        }

    @staticmethod
    def _public_uri(
        value: str,
        *,
        max_length: int = 500,
        replacements: _SecretReplacements = (),
    ) -> str:
        if len(value) > _MAX_PUBLIC_SCALAR_INPUT:
            marker = _replace_known_secrets("[oversized-uri]", replacements)
            return redact_text(marker, public=True, max_length=max_length)
        redacted = sanitize_uri(value, public=True)
        redacted = _replace_known_secrets(redacted, replacements)
        if len(redacted) <= max_length:
            return redacted
        return redacted[:max_length] + "..."

    @staticmethod
    def _secret_replacements(report: Report) -> _SecretReplacements:
        candidates: dict[str, set[str]] = {}
        for finding in report.findings:
            if finding.category != Category.SECRET or not finding.extracted_value:
                continue
            raw = finding.extracted_value
            masked = (
                finding.masked_value
                if finding.masked_value and finding.masked_value != raw
                else REDACTED
            )
            candidates.setdefault(raw, set()).add(masked)
            lowered = raw.lower()
            if lowered != raw:
                candidates.setdefault(lowered, set()).add(masked)
        replacements = tuple(
            (raw, sorted(masks)[0])
            for raw, masks in sorted(
                candidates.items(),
                key=lambda item: (-len(item[0]), item[0]),
            )
        )
        if not replacements:
            return ()
        return _SecretReplacementIndex(replacements)

    @staticmethod
    def _public_text(
        value: str,
        replacements: _SecretReplacements,
        *,
        max_length: int,
    ) -> str:
        if len(value) > _MAX_PUBLIC_SCALAR_INPUT:
            value = "[oversized-redacted]"
        value = _replace_known_secrets(value, replacements)
        return redact_text(value, public=True, max_length=max_length)

    def _id(self, kind: str, raw_id: str, namespace: str = "") -> str:
        return opaque_public_id(
            self._signing_key,
            kind,
            raw_id,
            namespace=namespace,
        )

    @staticmethod
    def _public_issue_payload(issue: Any) -> dict[str, object]:
        raw_code = getattr(issue, "code", None)
        raw_stage = getattr(issue, "stage", None)
        code = (
            raw_code
            if isinstance(raw_code, str) and raw_code in _PUBLIC_ISSUE_CODES
            else "analysis_incomplete"
        )
        stage = (
            raw_stage
            if isinstance(raw_stage, str) and raw_stage in _PUBLIC_ISSUE_STAGES
            else "unknown"
        )
        return {
            "code": code,
            "stage": stage,
            "message": f"Analysis coverage was reduced ({code})",
            "retryable": bool(issue.retryable),
            "affected_count": issue.affected_count,
            "details": PublicReportProjector._public_issue_details(issue.details),
        }

    @staticmethod
    def _public_issue_details(details: object) -> dict[str, object]:
        """Project only fixed numeric/boolean counters; arbitrary diagnostic text stays private."""
        if not isinstance(details, dict):
            return {}
        projected: dict[str, object] = {}
        for key in sorted(_PUBLIC_NUMERIC_DETAIL_KEYS.intersection(details)):
            value = details[key]
            if isinstance(value, bool):
                projected[key] = value
            elif isinstance(value, int):
                projected[key] = value if 0 <= value <= _MAX_PUBLIC_COUNTER else None
            elif isinstance(value, float):
                projected[key] = (
                    value
                    if math.isfinite(value) and 0 <= value <= _MAX_PUBLIC_COUNTER
                    else None
                )
        capped_passes = details.get("capped_passes")
        if isinstance(capped_passes, dict):
            public_caps: dict[str, int | None] = {}
            for name in sorted(_PUBLIC_CAPPED_PASS_NAMES.intersection(capped_passes)):
                count = capped_passes[name]
                public_caps[name] = (
                    count
                    if not isinstance(count, bool)
                    and isinstance(count, int)
                    and 1 <= count <= _MAX_PUBLIC_COUNTER
                    else None
                )
            if public_caps:
                projected["capped_passes"] = public_caps
        return projected

    def _encode_cursor(self, state: dict[str, object]) -> str:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(self, cursor: str) -> dict[str, object]:
        if not isinstance(cursor, str) or len(cursor) > _MAX_CURSOR_LENGTH:
            raise CursorError("cursor is malformed")
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            packed = base64.urlsafe_b64decode(padded.encode("ascii"))
            canonical = base64.urlsafe_b64encode(packed).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(cursor, canonical):
                raise CursorError("cursor encoding is not canonical")
            payload, signature = packed[:-32], packed[-32:]
            expected = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
            if len(signature) != 32 or not hmac.compare_digest(signature, expected):
                raise CursorError("cursor signature is invalid")
            state = json.loads(payload)
            if not isinstance(state, dict):
                raise CursorError("cursor payload is invalid")
            return state
        except CursorError:
            raise
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise CursorError("cursor is malformed") from exc
