"""
Configuration management for BundleInspector.

Provides configuration classes for all aspects of the tool.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from bundleInspector.utils.yaml_loader import load_yaml


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

class ScopeConfig(BaseModel):
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

class AuthConfig(BaseModel):
    """Authentication configuration."""
    model_config = ConfigDict(validate_assignment=True)

    # Cookies
    cookies: dict[str, str] = Field(default_factory=dict)

    # Headers
    headers: dict[str, str] = Field(default_factory=dict)

    # Bearer token
    bearer_token: Optional[str] = None

    # Basic auth
    basic_auth: Optional[tuple[str, str]] = None

    @model_validator(mode='after')
    def validate_headers(self) -> 'AuthConfig':
        """Validate header names and values."""
        for name, value in self.headers.items():
            if not name or not name.strip():
                raise ValueError(f"Empty header name is not allowed")
            if any(c in name for c in ('\r', '\n', '\x00')):
                raise ValueError(f"Invalid characters in header name: {name!r}")
            if any(c in value for c in ('\r', '\n', '\x00')):
                raise ValueError(f"Invalid characters in header value for '{name}'")
        # Validate bearer token for CRLF injection
        if self.bearer_token and any(c in self.bearer_token for c in ('\r', '\n', '\x00')):
            raise ValueError("Invalid characters in bearer token")
        # Validate basic auth for CRLF injection
        if self.basic_auth:
            for part in self.basic_auth:
                if any(c in part for c in ('\r', '\n', '\x00')):
                    raise ValueError("Invalid characters in basic auth credentials")
        return self

    def get_auth_headers(self) -> dict[str, str]:
        """Get all authentication headers."""
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

class CrawlerConfig(BaseModel):
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


# =============================================================================
# Parser Configuration
# =============================================================================

class ParserConfig(BaseModel):
    """Parser configuration."""
    # Tolerance
    tolerant: bool = True
    partial_on_error: bool = True

    # Features
    extract_strings: bool = True
    extract_calls: bool = True
    extract_imports: bool = True
    build_call_graph: bool = False  # More expensive

    # Beautify
    beautify: bool = True
    resolve_sourcemaps: bool = True


# =============================================================================
# Rule Configuration
# =============================================================================

class RuleConfig(BaseModel):
    """Rule engine configuration."""
    # Enabled categories
    enabled_categories: list[str] = Field(default_factory=lambda: [
        "endpoint", "secret", "domain", "flag", "debug"
    ])

    # Custom rules file
    custom_rules_file: Optional[Path] = None

    # Confidence thresholds
    min_confidence: str = "low"  # low, medium, high

    # Secret detection
    mask_secrets: bool = True
    secret_visible_chars: int = 4
    entropy_threshold: float = 3.5

    # Endpoint detection
    extract_headers: bool = True
    extract_parameters: bool = True


# =============================================================================
# Output Configuration
# =============================================================================

class OutputConfig(BaseModel):
    """Output configuration."""
    # Format
    format: OutputFormat = OutputFormat.JSON

    # Files
    output_file: Optional[Path] = None
    output_dir: Optional[Path] = None

    # Content
    include_raw_content: bool = False
    include_ast: bool = False
    include_snippets: bool = True
    snippet_context_lines: int = 3

    # Filtering
    min_severity: str = "info"
    min_risk_tier: str = "P3"


# =============================================================================
# Main Configuration
# =============================================================================

class Config(BaseModel):
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
    temp_dir: Optional[Path] = None

    # Job
    job_id: Optional[str] = None
    resume: bool = False

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from YAML/JSON file."""
        import json

        content = path.read_text()

        if path.suffix in (".yaml", ".yml"):
            data = load_yaml(content)
        else:
            data = json.loads(content)

        return cls.model_validate(data)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode="json")

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

def get_default_config() -> Config:
    """Get default configuration."""
    return Config()


def create_config(
    seed_urls: list[str],
    scope_domains: Optional[list[str]] = None,
    auth_cookies: Optional[dict[str, str]] = None,
    auth_headers: Optional[dict[str, str]] = None,
    depth: int = 3,
    rate_limit: float = 1.0,
    headless: bool = True,
    output_format: str = "json",
    output_file: Optional[str] = None,
    verbose: bool = False,
    bearer_token: Optional[str] = None,
    basic_auth: Optional[tuple[str, str]] = None,
    user_agent: Optional[str] = None,
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

