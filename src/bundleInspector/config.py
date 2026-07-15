"""
Configuration management for BundleInspector.

Provides configuration classes for all aspects of the tool.
"""

from __future__ import annotations

import math
import re
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bundleInspector.storage.identifiers import validate_portable_component
from bundleInspector.utils.yaml_loader import load_yaml


class StrictConfigModel(BaseModel):
    """Fail-closed base for user-controlled configuration."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


_AUTH_CONTROL_CHARACTERS = frozenset({"\r", "\n", "\x00"})


def _validate_cookie_mapping(values: dict[str, str]) -> dict[str, str]:
    for name, value in values.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Empty cookie name is not allowed")
        if not isinstance(value, str):
            raise ValueError(f"Cookie value for {name!r} must be a string")
        if any(character in name for character in _AUTH_CONTROL_CHARACTERS):
            raise ValueError(f"Invalid characters in cookie name: {name!r}")
        if any(character in value for character in _AUTH_CONTROL_CHARACTERS):
            raise ValueError(f"Invalid characters in cookie value for '{name}'")
    return values


def _validate_header_mapping(
    values: dict[str, str],
    *,
    reject_transport_controlled: bool = True,
) -> dict[str, str]:
    for name, value in values.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Empty header name is not allowed")
        if not isinstance(value, str):
            raise ValueError(f"Header value for {name!r} must be a string")
        if any(character in name for character in _AUTH_CONTROL_CHARACTERS):
            raise ValueError(f"Invalid characters in header name: {name!r}")
        if any(character in value for character in _AUTH_CONTROL_CHARACTERS):
            raise ValueError(f"Invalid characters in header value for '{name}'")
        if (
            reject_transport_controlled
            and name.strip().lower() in {"host", "content-length", "transfer-encoding"}
        ):
            raise ValueError(f"Transport-controlled header is not allowed: {name!r}")
    return values


def _validate_bearer_token(value: str | None) -> str | None:
    if value and any(character in value for character in _AUTH_CONTROL_CHARACTERS):
        raise ValueError("Invalid characters in bearer token")
    return value


def _validate_basic_auth(value: tuple[str, str] | None) -> tuple[str, str] | None:
    if value and any(
        character in part
        for part in value
        for character in _AUTH_CONTROL_CHARACTERS
    ):
        raise ValueError("Invalid characters in basic auth credentials")
    return value


class ThirdPartyPolicy(str, Enum):
    """Policy for handling third-party JS."""
    ANALYZE = "analyze"      # Analyze and include in findings
    SKIP = "skip"           # Skip entirely
    TAG_ONLY = "tag_only"   # Analyze but tag as third-party


class OutputFormat(str, Enum):
    """Output report format."""
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class LogLevel(str, Enum):
    """Logging level."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# =============================================================================
# Scope Configuration
# =============================================================================

class ScopeConfig(StrictConfigModel):
    """Scope policy configuration."""
    # Domain rules
    allowed_domains: list[str] = Field(default_factory=list)
    denied_domains: list[str] = Field(default_factory=list)
    include_subdomains: bool = True

    # Path rules
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)

    # Third-party handling
    third_party_policy: ThirdPartyPolicy = ThirdPartyPolicy.TAG_ONLY

    # SSRF opt-in: allow scanning targets that resolve to private/internal IP ranges
    # (RFC1918/CGNAT/ULA) for AUTHORIZED internal/dev-server testing. Default off keeps full
    # SSRF protection. Loopback / cloud-metadata / multicast / reserved stay blocked regardless.
    allow_private_ips: bool = False

    # CDN patterns (common JS CDNs)
    cdn_patterns: list[str] = Field(default_factory=lambda: [
        "cdn.jsdelivr.net", "*.cdn.jsdelivr.net",
        "cdnjs.cloudflare.com", "*.cdnjs.cloudflare.com",
        "unpkg.com", "*.unpkg.com",
        "googleapis.com", "*.googleapis.com",
        "gstatic.com", "*.gstatic.com",
        "cloudflare.com", "*.cloudflare.com",
        "bootstrapcdn.com", "*.bootstrapcdn.com",
        "jquery.com", "*.jquery.com",
    ])

    @field_validator("allowed_domains", "denied_domains", "cdn_patterns")
    @classmethod
    def _validate_domain_patterns(cls, values: list[str], info: Any) -> list[str]:
        if len(values) > 100:
            raise ValueError(f"{info.field_name} supports at most 100 patterns")
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"invalid domain pattern in {info.field_name}")
            if value.count("*") > 2:
                raise ValueError(f"domain pattern has too many wildcards: {value!r}")
        return values

    def add_seed_domain(self, url: str) -> None:
        """Add domain from seed URL to allowed list."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Use hostname (without port) for domain matching, but also add
        # the full netloc (with port) so URLs with ports match too
        domain = parsed.hostname or parsed.netloc
        if domain:
            # Always add wildcard for subdomains (even if exact domain already present)
            if self.include_subdomains:
                wildcard = f"*.{domain}"
                if wildcard not in self.allowed_domains:
                    self.allowed_domains.append(wildcard)
            if domain not in self.allowed_domains:
                self.allowed_domains.append(domain)
        # Always check and add netloc with port if different (even if hostname already added)
        netloc = parsed.netloc.lower() if parsed.netloc else ""
        if netloc and netloc != domain and netloc not in self.allowed_domains:
            self.allowed_domains.append(netloc)


# =============================================================================
# Authentication Configuration
# =============================================================================

class AuthConfig(StrictConfigModel):
    """Authentication configuration."""
    # Cookies
    cookies: dict[str, str] = Field(default_factory=dict)

    # Headers
    headers: dict[str, str] = Field(default_factory=dict)

    # Bearer token
    bearer_token: str | None = None

    # Basic auth
    basic_auth: tuple[str, str] | None = None

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, values: dict[str, str]) -> dict[str, str]:
        """Reject cookie injection before construction or assignment commits."""
        return _validate_cookie_mapping(values)

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, values: dict[str, str]) -> dict[str, str]:
        """Reject header injection before construction or assignment commits."""
        return _validate_header_mapping(values)

    @field_validator("bearer_token")
    @classmethod
    def validate_bearer_token(cls, value: str | None) -> str | None:
        return _validate_bearer_token(value)

    @field_validator("basic_auth")
    @classmethod
    def validate_basic_auth(cls, value: tuple[str, str] | None) -> tuple[str, str] | None:
        return _validate_basic_auth(value)

    def get_auth_headers(self) -> dict[str, str]:
        """Get all authentication headers."""
        # Pydantic validates field replacement, but callers can still mutate the two dictionaries
        # in place. Revalidate at the shared transport-preparation boundary so that cannot turn
        # into a request-smuggling/header-injection path.
        _validate_cookie_mapping(self.cookies)
        # Transport-controlled names are rejected on normal construction/assignment. If an
        # unsafe model or in-place mutation bypasses that boundary, the origin-bound transport
        # filter still removes those names; keep this shared check focused on injection controls.
        _validate_header_mapping(self.headers, reject_transport_controlled=False)
        _validate_bearer_token(self.bearer_token)
        _validate_basic_auth(self.basic_auth)
        headers = dict(self.headers)

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.basic_auth:
            import base64
            credentials = base64.b64encode(
                f"{self.basic_auth[0]}:{self.basic_auth[1]}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers


# =============================================================================
# Crawler Configuration
# =============================================================================

class CrawlerConfig(StrictConfigModel):
    """Crawler configuration."""
    # Crawling behavior
    max_depth: int = 3
    max_pages: int = 100
    max_js_files: int = 1000

    # Rate limiting
    rate_limit: float = 1.0  # Seconds between requests
    max_concurrent: int = 10

    # Timeouts
    request_timeout: float = 30.0
    page_timeout: float = 60.0

    # Redirect limits (security)
    max_redirects: int = 10  # Prevent redirect loops/attacks
    follow_redirects: bool = True

    # Headless browser
    use_headless: bool = True
    headless_wait_time: float = 2.0  # Wait after page load
    explore_routes: bool = True
    max_route_exploration: int = 20

    # Interactive UI exploration: clicking buttons/tabs/role elements to trigger lazy-loaded
    # JS chunks. OFF by default -- such clicks are the highest-risk way to drive the app to
    # issue its own state-changing requests (form submits, deletes, purchases). Route-link
    # exploration (explore_routes) stays on but is covered by the same guard below.
    interactive_clicking: bool = False
    # Session guard: while the tool is actively driving the UI (route-link + interactive
    # clicks), block any non-idempotent (POST/PUT/PATCH/DELETE) request it induces instead of
    # sending it to the target. The endpoint is still recorded (so discovery is not lost); a
    # wired confirmation handler is asked first (pause-and-confirm) and the request proceeds
    # only if approved. Default ON. Service workers are blocked while this is on so no request
    # bypasses the guard. Disable only on a target you own and intend to mutate.
    block_state_changing_requests: bool = True

    # Retry
    max_retries: int = 3
    retry_delay: float = 1.0

    # User agent
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # File limits
    max_file_size: int = 10 * 1024 * 1024  # 10MB

    # DQ-O07: fail CLOSED on out-of-range limits instead of silently producing a degenerate crawl.
    @field_validator("max_depth", "max_pages", "max_js_files", "max_redirects",
                     "max_route_exploration", "max_retries", "max_file_size")
    @classmethod
    def _reject_negative_ints(cls, v: int, info: Any) -> int:
        if isinstance(v, int) and v < 0:
            raise ValueError(f"{info.field_name} must be >= 0, got {v}")
        return v

    @field_validator("rate_limit", "request_timeout", "page_timeout", "headless_wait_time", "retry_delay")
    @classmethod
    def _reject_bad_floats(cls, v: float, info: Any) -> float:
        if isinstance(v, (int, float)) and (not math.isfinite(v) or v < 0):
            raise ValueError(f"{info.field_name} must be finite and >= 0, got {v}")
        return v

    @field_validator("max_concurrent")
    @classmethod
    def _require_positive_concurrency(cls, v: int) -> int:
        if isinstance(v, int) and v < 1:
            raise ValueError(f"max_concurrent must be >= 1, got {v}")
        return v


# =============================================================================
# Parser Configuration
# =============================================================================

class ParserConfig(StrictConfigModel):
    """Parser configuration."""
    # Tolerance
    tolerant: bool = True
    partial_on_error: bool = True

    # Features
    extract_strings: bool = True
    extract_calls: bool = True
    extract_imports: bool = True
    # DQ-P13: default True to match the actual pipeline behavior (build_ir has always built the call
    # graph unconditionally, and detectors/correlator depend on it). This flag is now honored, so a
    # caller can set it False to skip the (more expensive) call-graph construction.
    build_call_graph: bool = True

    # Beautify
    beautify: bool = True
    resolve_sourcemaps: bool = True
    beautify_max_bytes: int = 1_000_000
    analysis_worker_timeout: float = 30.0

    @field_validator("beautify_max_bytes")
    @classmethod
    def _validate_beautify_limit(cls, value: int) -> int:
        if value < 0:
            raise ValueError("beautify_max_bytes must be >= 0")
        return value

    @field_validator("analysis_worker_timeout")
    @classmethod
    def _validate_worker_timeout(cls, value: float) -> float:
        if not math.isfinite(value) or not 0.1 <= value <= 600:
            raise ValueError("analysis_worker_timeout must be finite and in [0.1, 600]")
        return value


# =============================================================================
# Rule Configuration
# =============================================================================

class RuleConfig(StrictConfigModel):
    """Rule engine configuration."""
    # Enabled categories
    enabled_categories: list[str] = Field(default_factory=lambda: [
        "endpoint", "secret", "domain", "flag", "debug", "sink", "upload"
    ])

    # Custom rules file
    custom_rules_file: Path | None = None

    # Confidence thresholds
    min_confidence: str = "low"  # low, medium, high

    @field_validator("min_confidence")
    @classmethod
    def _validate_min_confidence(cls, v: str) -> str:
        """Fail CLOSED on a typo/misconfig instead of silently disabling confidence filtering
        (mirrors the loud handling of unknown enabled_categories). Case/whitespace are normalized."""
        valid = {"low", "medium", "high"}
        norm = v.strip().lower() if isinstance(v, str) else v
        if norm not in valid:
            raise ValueError(f"min_confidence must be one of {sorted(valid)}, got {v!r}")
        return norm

    # Secret detection
    mask_secrets: bool = True
    secret_visible_chars: int = 4
    entropy_threshold: float = 3.5

    @field_validator("entropy_threshold")
    @classmethod
    def _validate_entropy_threshold(cls, v: float) -> float:
        # DQ-O07: NaN/Inf entropy makes filtering non-deterministic; reject it.
        if not math.isfinite(v) or v < 0:
            raise ValueError(f"entropy_threshold must be finite and >= 0, got {v!r}")
        return v

    @field_validator("secret_visible_chars")
    @classmethod
    def _validate_secret_visible_chars(cls, v: int) -> int:
        if isinstance(v, int) and not (0 <= v <= 1024):
            raise ValueError(f"secret_visible_chars must be in [0, 1024], got {v}")
        return v

    # Endpoint detection
    extract_headers: bool = True
    extract_parameters: bool = True

    # enh1: client-side access-control gating detection
    client_side_gating_enabled: bool = True
    client_side_gating_severity: str = "medium"

    @field_validator("enabled_categories")
    @classmethod
    def _normalize_categories(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]
        valid = {"endpoint", "secret", "domain", "flag", "debug", "sink", "upload"}
        unknown = [value for value in normalized if value not in valid]
        if unknown:
            raise ValueError(f"unknown enabled_categories: {unknown}")
        return list(dict.fromkeys(normalized))

    @field_validator("client_side_gating_severity")
    @classmethod
    def _validate_gating_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("client_side_gating_severity is invalid")
        return normalized

    # enh2: dormant / hidden endpoint detection (declared in JS but never called at runtime)
    dormant_endpoint_detection_enabled: bool = True

    # enh7: runtime endpoint surfacing (HTTP/WS the app CALLED at runtime but static analysis
    # never found -- the complement of dormant detection). Scan-only; first-party scoped.
    runtime_endpoint_surfacing_enabled: bool = True


# =============================================================================
# Output Configuration
# =============================================================================

class OutputConfig(StrictConfigModel):
    """Output configuration."""
    # Format
    format: OutputFormat = OutputFormat.JSON

    # Files
    output_file: Path | None = None
    output_dir: Path | None = None

    # Content
    include_raw_content: bool = False
    include_ast: bool = False
    include_snippets: bool = True
    snippet_context_lines: int = 3

    @field_validator("snippet_context_lines")
    @classmethod
    def _validate_snippet_context(cls, value: int) -> int:
        if not 0 <= value <= 50:
            raise ValueError("snippet_context_lines must be in [0, 50]")
        return value

    # Filtering
    min_severity: str = "info"
    min_risk_tier: str = "P3"

    # DQ-O07: reject a garbage severity/tier (was an inert string) so misconfig fails closed.
    @field_validator("min_severity")
    @classmethod
    def _validate_min_severity(cls, v: str) -> str:
        valid = {"info", "low", "medium", "high", "critical"}
        norm = v.strip().lower() if isinstance(v, str) else v
        if norm not in valid:
            raise ValueError(f"min_severity must be one of {sorted(valid)}, got {v!r}")
        return norm

    @field_validator("min_risk_tier")
    @classmethod
    def _validate_min_risk_tier(cls, v: str) -> str:
        valid = {"P0", "P1", "P2", "P3"}
        norm = v.strip().upper() if isinstance(v, str) else v
        if norm not in valid:
            raise ValueError(f"min_risk_tier must be one of {sorted(valid)}, got {v!r}")
        return norm


# =============================================================================
# Main Configuration
# =============================================================================

class Config(StrictConfigModel):
    """Main configuration for BundleInspector."""
    # Sub-configurations
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    parser: ParserConfig = Field(default_factory=ParserConfig)
    rules: RuleConfig = Field(default_factory=RuleConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    # Logging
    log_level: LogLevel = LogLevel.INFO
    verbose: bool = False
    quiet: bool = False

    # Storage
    cache_dir: Path = Field(
        default_factory=lambda: Path.home() / ".bundleInspector" / "cache"
    )
    temp_dir: Path | None = None

    # Job
    job_id: str | None = None
    resume: bool = False

    @field_validator("job_id")
    @classmethod
    def _validate_job_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_portable_component(value, label="job_id")

    @classmethod
    def from_file(cls, path: Path) -> Config:
        """Load configuration from YAML/JSON file."""
        import json

        # utf-8-sig tolerates a UTF-8 BOM (common from Windows editors) which plain utf-8
        # would leave in place and crash json.loads / the YAML loader.
        content = path.read_text(encoding="utf-8-sig")

        if path.suffix in (".yaml", ".yml"):
            data = load_yaml(content)
        else:
            data = json.loads(content)

        return cls.model_validate(data)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode="json")

    def to_report_dict(self) -> dict[str, Any]:
        """Serialize analysis settings without serializing credential material."""
        data = self.to_dict()
        auth_kinds: list[str] = []
        if self.auth.cookies:
            auth_kinds.append("cookies")
        if self.auth.headers:
            auth_kinds.append("headers")
        if self.auth.bearer_token:
            auth_kinds.append("bearer")
        if self.auth.basic_auth:
            auth_kinds.append("basic")
        data["auth"] = {
            "auth_configured": bool(auth_kinds),
            "types": auth_kinds,
        }
        return data

    def ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback = Path.cwd() / ".bundleInspector" / "cache"
            fallback.mkdir(parents=True, exist_ok=True)
            self.cache_dir = fallback
        if self.temp_dir:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
        if self.output.output_dir:
            self.output.output_dir.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Configuration helpers
# =============================================================================

def redact_config_secrets(config_dict: dict[str, Any]) -> dict[str, Any]:
    """Return a COPY of a serialized config with auth credentials redacted, so an embedded/stored
    report (JSON/HTML/cache/MCP) never carries live bearer tokens, basic-auth, cookies, or
    Authorization headers in cleartext (DQ-O13). Resume-signature computation must keep using the RAW
    to_dict(), not this -- so signatures stay stable."""
    import copy

    redacted = copy.deepcopy(config_dict)
    auth = redacted.get("auth")
    if isinstance(auth, dict):
        for key in ("bearer_token", "basic_auth", "password", "client_secret"):
            if auth.get(key):
                auth[key] = "***redacted***"
        if isinstance(auth.get("cookies"), dict) and auth["cookies"]:
            auth["cookies"] = dict.fromkeys(auth["cookies"], "***redacted***")
        if isinstance(auth.get("headers"), dict):
            sensitive_header = re.compile(
                r"(?:authorization|cookie|api[-_]?key|auth[-_]?token|access[-_]?token|secret|credential)",
                re.IGNORECASE,
            )
            auth["headers"] = {
                k: ("***redacted***" if isinstance(k, str) and sensitive_header.search(k) else v)
                for k, v in auth["headers"].items()
            }
    return redacted


def get_default_config() -> Config:
    """Get default configuration."""
    return Config()


def create_config(
    seed_urls: list[str],
    scope_domains: list[str] | None = None,
    auth_cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
    depth: int = 3,
    rate_limit: float = 1.0,
    headless: bool = True,
    output_format: str = "json",
    output_file: str | None = None,
    verbose: bool = False,
    bearer_token: str | None = None,
    basic_auth: tuple[str, str] | None = None,
    user_agent: str | None = None,
) -> Config:
    """Create configuration from common parameters."""
    crawler_kwargs: dict[str, Any] = {
        "max_depth": depth,
        "rate_limit": rate_limit,
        "use_headless": headless,
    }
    if user_agent:
        crawler_kwargs["user_agent"] = user_agent

    config = Config(
        auth=AuthConfig(
            cookies=auth_cookies or {},
            headers=auth_headers or {},
            bearer_token=bearer_token,
            basic_auth=basic_auth,
        ),
        crawler=CrawlerConfig(**crawler_kwargs),
        output=OutputConfig(
            format=OutputFormat(output_format),
            output_file=Path(output_file) if output_file else None,
        ),
        verbose=verbose,
    )

    # Add scope from seed URLs
    for url in seed_urls:
        config.scope.add_seed_domain(url)

    # Add explicit scope domains
    if scope_domains:
        config.scope.allowed_domains.extend(scope_domains)

    return config
