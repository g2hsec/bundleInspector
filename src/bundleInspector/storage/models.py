"""
Data models for BundleInspector.

All core data structures used throughout the application.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, field_serializer, field_validator


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Confidence levels for findings."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    """Finding categories."""
    ENDPOINT = "endpoint"
    SECRET = "secret"
    DOMAIN = "domain"
    FLAG = "flag"
    DEBUG = "debug"
    SINK = "sink"        # DOM-XSS / code-injection sinks (innerHTML, .html(), eval, ...)
    UPLOAD = "upload"    # file-upload surface (FormData, client-side-only validation)


class RiskTier(str, Enum):
    """Risk priority tiers."""
    P0 = "P0"  # Critical - immediate action required
    P1 = "P1"  # High - action required
    P2 = "P2"  # Medium - should investigate
    P3 = "P3"  # Low - informational


class CompletenessStatus(str, Enum):
    """Whether a report represents all work requested by its scan profile."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CompletenessIssue(BaseModel):
    """Machine-readable evidence that analysis coverage was reduced."""

    code: str
    stage: str
    message: str
    retryable: bool = False
    affected_count: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class AnalysisCompleteness(BaseModel):
    """Coverage state shared by checkpoints, reports, reporters, and public projections."""

    status: CompletenessStatus = CompletenessStatus.COMPLETE
    issues: list[CompletenessIssue] = Field(default_factory=list)

    @computed_field
    def is_complete(self) -> bool:
        return self.status == CompletenessStatus.COMPLETE and not self.issues

    @computed_field
    def retryable(self) -> bool:
        return any(issue.retryable for issue in self.issues)


class LoadMethod(str, Enum):
    """How the JS file was loaded."""
    SCRIPT_TAG = "script_tag"
    DYNAMIC_IMPORT = "dynamic_import"
    PRELOAD = "preload"
    MODULE_PRELOAD = "module_preload"
    INLINE = "inline"
    NETWORK_CAPTURE = "network_capture"
    MANIFEST = "manifest"
    LOCAL_FILE = "local_file"


class AssetSource(str, Enum):
    """Source of the asset."""
    STATIC = "static"       # Static HTML parsing
    HEADLESS = "headless"   # Headless browser
    MANIFEST = "manifest"   # Build manifest
    LOCAL = "local"         # Local filesystem


class EdgeType(str, Enum):
    """Correlation edge types."""
    SAME_FILE = "same_file"
    IMPORT = "import"
    CALL_CHAIN = "call_chain"
    CONFIG = "config"
    ENV = "env"
    RUNTIME = "runtime"
    TAINT = "taint"  # light dataflow: a source (upload surface / response field) reaches a DOM sink


# =============================================================================
# JS Asset Models
# =============================================================================

class JSReference(BaseModel):
    """Reference to a JS file discovered during crawling."""
    url: str
    initiator: str = ""  # URL/script that triggered this load
    load_context: str = ""  # Route/page context
    method: LoadMethod = LoadMethod.SCRIPT_TAG
    headers: dict[str, str] = Field(default_factory=dict)
    # In-page inline <script> body (DQ-I01). When set, the ref has no fetchable URL: the download
    # stage synthesizes the asset directly from this content, bypassing SSRF/HTTP/rate-limit.
    inline_content: str | None = None
    # Browser-authenticated response bodies must survive a crawl checkpoint so resume does not
    # refetch without the browser session. FindingStore seals the whole checkpoint with AES-GCM;
    # reports and public projections never contain JSReference objects.
    captured_content: bytes | None = Field(default=None, repr=False)
    captured_status_code: int = 200
    provenance: list[AssetProvenance] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_serializer("captured_content", when_used="json")
    def _serialize_captured_content(self, value: bytes | None) -> str | None:
        return base64.b64encode(value).decode("ascii") if value is not None else None

    @field_validator("captured_content", mode="before")
    @classmethod
    def _deserialize_captured_content(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise ValueError("captured_content must be valid base64") from exc
        return value


class AssetProvenance(BaseModel):
    """One deterministic discovery path for content that may appear at several URLs."""
    url: str
    initiator: str = ""
    load_context: str = ""
    method: LoadMethod = LoadMethod.SCRIPT_TAG


class JSAsset(BaseModel):
    """A collected JavaScript asset."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    content_hash: str = ""  # SHA-256 of content
    size: int = 0
    content: bytes = b""  # Raw content (stored separately in practice)
    language_hint: Literal["javascript", "jsx", "typescript", "tsx"] | None = None

    # Source
    source: AssetSource = AssetSource.STATIC

    # Source map
    has_sourcemap: bool = False
    sourcemap_url: str | None = None
    sourcemap_hash: str | None = None
    sourcemap_content: bytes | None = None

    # Loading context
    initiator: str = ""
    load_context: str = ""
    load_method: LoadMethod = LoadMethod.SCRIPT_TAG
    is_first_party: bool = True
    provenance: list[AssetProvenance] = Field(default_factory=list)

    # HTTP metadata
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int = 200
    etag: str | None = None
    last_modified: str | None = None
    fetch_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Processing state
    normalized_hash: str | None = None
    ast_hash: str | None = None
    parse_success: bool = False
    parse_errors: list[str] = Field(default_factory=list)

    @field_serializer("content", "sourcemap_content", when_used="json")
    def _serialize_bytes_b64(self, value: bytes | None) -> str | None:
        """Base64-encode raw asset bytes for JSON output. Pydantic's default json bytes handling
        UTF-8-decodes, which raises UnicodeDecodeError on non-UTF8 bundles (crashed
        JSONReporter(include_raw=True) and the swallowed finding_store.store_report path). Scoped to
        json mode only (when_used="json"), so python-mode model_dump() and all validation/construction
        are untouched -- str/bytes inputs still validate as before (DQ FU-JSON)."""
        if value is None:
            return None
        return base64.b64encode(value).decode("ascii")

    @computed_field
    def content_type(self) -> str:
        return self.headers.get("content-type", "application/javascript")

    def compute_hash(self) -> str:
        """Compute and set content hash."""
        self.content_hash = hashlib.sha256(self.content).hexdigest()
        return self.content_hash


# =============================================================================
# Finding Models
# =============================================================================

class Evidence(BaseModel):
    """Evidence supporting a finding."""
    file_url: str
    file_hash: str
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""  # Code snippet with context
    snippet_lines: tuple[int, int] = (0, 0)  # Start/end lines of snippet
    ast_node_type: str = ""

    # Original position (before beautify)
    original_file_url: str | None = None
    original_line: int | None = None
    original_column: int | None = None


class Finding(BaseModel):
    """A security finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence

    # Description
    title: str
    description: str = ""

    # Evidence
    evidence: Evidence

    # Extracted value
    extracted_value: str
    value_type: str = ""  # api_key, jwt, url, domain, etc.
    masked_value: str | None = None  # Masked version for reports

    @computed_field
    def value_hash(self) -> str:
        """Hash of extracted value for deduplication."""
        return hashlib.sha256(self.extracted_value.encode()).hexdigest()[:16]

    # Risk
    risk_tier: RiskTier | None = None
    risk_score: float = Field(default=0.0, allow_inf_nan=False)
    impact_score: float = Field(default=0.0, allow_inf_nan=False)
    likelihood_score: float = Field(default=0.0, allow_inf_nan=False)

    # Correlation
    correlation_ids: list[str] = Field(default_factory=list)
    cluster_id: str | None = None

    # Metadata
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def mask_value(self, visible_chars: int = 4) -> str:
        """Create masked version of extracted value."""
        value = self.extracted_value
        visible_chars = max(0, visible_chars)
        if not value:
            self.masked_value = ""
            return self.masked_value
        if len(value) <= visible_chars * 2:
            self.masked_value = "*" * len(value)
        else:
            # Keep the model method aligned with core.security.mask_sensitive_value: even for a
            # large requested window, no side can reveal more than one quarter of the value.
            effective = min(visible_chars, len(value) // 4)
            end_part = value[-effective:] if effective > 0 else ""
            self.masked_value = (
                value[:effective] +
                "*" * (len(value) - effective * 2) +
                end_part
            )
        return self.masked_value


# =============================================================================
# Correlation Models
# =============================================================================

class Edge(BaseModel):
    """A correlation edge between findings."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    edge_type: EdgeType
    confidence: Confidence = Confidence.MEDIUM
    reasoning: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Correlation(BaseModel):
    """Correlation between findings."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    edge_type: EdgeType
    source_finding_id: str
    target_finding_id: str
    confidence: Confidence
    reasoning: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Cluster(BaseModel):
    """A cluster of related findings."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    common_traits: dict[str, Any] = Field(default_factory=dict)

    # Statistics
    @computed_field
    def size(self) -> int:
        return len(self.finding_ids)


# =============================================================================
# Report Models
# =============================================================================

class ReportSummary(BaseModel):
    """Summary statistics for a report."""
    total_js_files: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    findings_by_tier: dict[str, int] = Field(default_factory=dict)
    total_correlations: int = 0
    total_clusters: int = 0


class Report(BaseModel):
    """Complete analysis report."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    duration_seconds: float = Field(default=0.0, allow_inf_nan=False)

    # Input
    seed_urls: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    # Summary
    summary: ReportSummary = Field(default_factory=ReportSummary)

    # Results
    assets: list[JSAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)

    # Errors
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    completeness: AnalysisCompleteness = Field(default_factory=AnalysisCompleteness)

    def compute_summary(self) -> ReportSummary:
        """Compute summary statistics."""
        self.summary = ReportSummary(
            total_js_files=len(self.assets),
            total_findings=len(self.findings),
            findings_by_severity={
                sev.value: sum(1 for f in self.findings if f.severity == sev)
                for sev in Severity
            },
            findings_by_category={
                cat.value: sum(1 for f in self.findings if f.category == cat)
                for cat in Category
            },
            findings_by_tier={
                tier.value: sum(1 for f in self.findings if f.risk_tier == tier)
                for tier in RiskTier
            },
            total_correlations=len(self.correlations),
            total_clusters=len(self.clusters),
        )
        return self.summary


# =============================================================================
# IR Models (for parser)
# =============================================================================

class StringLiteral(BaseModel):
    """A string literal extracted from AST."""
    value: str
    raw: str | None = None
    line: int = 0
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None
    context: str = ""  # Parent node type


class FunctionCall(BaseModel):
    """A function call extracted from AST."""
    name: str
    full_name: str = ""  # e.g., axios.get, window.fetch
    arguments: list[Any] = Field(default_factory=list)
    scope: str = "global"
    line: int = 0
    column: int = 0


class ImportDecl(BaseModel):
    """An import declaration."""
    source: str
    specifiers: list[str] = Field(default_factory=list)
    is_dynamic: bool = False
    line: int = 0


class ExportDecl(BaseModel):
    """An export declaration."""
    name: str
    is_default: bool = False
    line: int = 0


class Identifier(BaseModel):
    """An identifier with scope info."""
    name: str
    scope: str = ""  # global, function, block
    line: int = 0
    column: int = 0


class FunctionDef(BaseModel):
    """A function definition with source range info."""
    name: str
    scope: str = ""
    line: int = 0
    end_line: int = 0
    start_offset: int = -1     # absolute char offset of the function's start (for enh1 early-return guards)
    end_offset: int = -1       # absolute char offset of the function's end (for enh1 early-return guards)


class GuardCondition(BaseModel):
    """enh1: a client-side conditional guarding a source region (for access-control detection)."""
    scope: str = ""
    node_kind: str = ""        # if | ternary | logical | early_return
    polarity: str = ""         # positive | negative_early_return
    guarded_start: int = 0
    guarded_end: int = 0
    test_start: int = 0
    test_end: int = 0
    test_start_line: int = 0
    # Absolute char-offset ranges (minified/single-line safe; line ranges collapse there).
    guarded_start_off: int = 0
    guarded_end_off: int = -1
    test_start_off: int = 0
    test_end_off: int = -1
    tokens: list[str] = Field(default_factory=list)
    kind: str = ""             # filled by classify_guard: role|permission|flag|feature|entitlement|generic-authz


class IntermediateRepresentation(BaseModel):
    """Intermediate representation of parsed JS."""
    file_url: str
    file_hash: str

    string_literals: list[StringLiteral] = Field(default_factory=list)
    function_calls: list[FunctionCall] = Field(default_factory=list)
    function_defs: list[FunctionDef] = Field(default_factory=list)
    imports: list[ImportDecl] = Field(default_factory=list)
    exports: list[ExportDecl] = Field(default_factory=list)
    identifiers: dict[str, list[Identifier]] = Field(default_factory=dict)
    call_graph: dict[str, list[str]] = Field(default_factory=dict)
    guard_conditions: list[GuardCondition] = Field(default_factory=list)

    # Raw AST (optional, for advanced analysis)
    raw_ast: dict[str, Any] | None = None

    # Parsing metadata
    partial: bool = False
    errors: list[str] = Field(default_factory=list)


# =============================================================================
# Checkpoint Models
# =============================================================================

class PipelineCheckpoint(BaseModel):
    """Serializable pipeline checkpoint for stage resume."""
    job_id: str
    seed_urls: list[str] = Field(default_factory=list)
    stage: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    js_refs: list[JSReference] = Field(default_factory=list)
    asset_hashes: list[str] = Field(default_factory=list)
    line_mappers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    sourcemaps: dict[str, dict[str, Any]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    stage_state: dict[str, Any] = Field(default_factory=dict)
    completeness: AnalysisCompleteness = Field(default_factory=AnalysisCompleteness)
