"""
Data models for BundleInspector.

All core data structures used throughout the application.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


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


class RiskTier(str, Enum):
    """Risk priority tiers."""
    P0 = "P0"  # Critical - immediate action required
    P1 = "P1"  # High - action required
    P2 = "P2"  # Medium - should investigate
    P3 = "P3"  # Low - informational


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
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class JSAsset(BaseModel):
    """A collected JavaScript asset."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    content_hash: str = ""  # SHA-256 of content
    size: int = 0
    content: bytes = b""  # Raw content (stored separately in practice)

    # Source
    source: AssetSource = AssetSource.STATIC

    # Source map
    has_sourcemap: bool = False
    sourcemap_url: Optional[str] = None
    sourcemap_hash: Optional[str] = None
    sourcemap_content: Optional[bytes] = None

    # Loading context
    initiator: str = ""
    load_context: str = ""
    load_method: LoadMethod = LoadMethod.SCRIPT_TAG
    is_first_party: bool = True

    # HTTP metadata
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int = 200
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    fetch_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Processing state
    normalized_hash: Optional[str] = None
    ast_hash: Optional[str] = None
    parse_success: bool = False
    parse_errors: list[str] = Field(default_factory=list)

    @computed_field
    @property
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
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    snippet: str = ""  # Code snippet with context
    snippet_lines: tuple[int, int] = (0, 0)  # Start/end lines of snippet
    ast_node_type: str = ""

    # Original position (before beautify)
    original_file_url: Optional[str] = None
    original_line: Optional[int] = None
    original_column: Optional[int] = None


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
    masked_value: Optional[str] = None  # Masked version for reports

    @computed_field
    @property
    def value_hash(self) -> str:
        """Hash of extracted value for deduplication."""
        return hashlib.sha256(self.extracted_value.encode()).hexdigest()[:16]

    # Risk
    risk_tier: Optional[RiskTier] = None
    risk_score: float = 0.0
    impact_score: float = 0.0
    likelihood_score: float = 0.0

    # Correlation
    correlation_ids: list[str] = Field(default_factory=list)
    cluster_id: Optional[str] = None

    # Metadata
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def mask_value(self, visible_chars: int = 4) -> str:
        """Create masked version of extracted value."""
        value = self.extracted_value
        # Cap visible chars to at most 25% of value length per side
        effective = min(visible_chars, max(1, len(value) // 4))
        if len(value) <= effective * 3:
            self.masked_value = "*" * len(value)
        else:
            self.masked_value = (
                value[:effective] +
                "*" * (len(value) - effective * 2) +
                value[-effective:]
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
    @property
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
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

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
    raw: Optional[str] = None
    line: int = 0
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
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

    # Raw AST (optional, for advanced analysis)
    raw_ast: Optional[dict[str, Any]] = None

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

