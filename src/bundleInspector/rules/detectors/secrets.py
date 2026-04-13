"""
Secret detector.

Detects hardcoded secrets, API keys, tokens, and credentials.
"""

from __future__ import annotations

import math
import re
from typing import Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)


class SecretDetector(BaseRule):
    """
    Detect hardcoded secrets in JavaScript.

    Uses multiple detection strategies:
    1. Pattern matching for known secret formats
    2. Entropy analysis for random-looking strings
    3. Context analysis for variable names
    """

    id = "secret-detector"
    name = "Secret Detector"
    description = "Detects hardcoded secrets, API keys, and credentials"
    category = Category.SECRET
    severity = Severity.HIGH

    # Known secret patterns with (pattern, type, severity)
    SECRET_PATTERNS = [
        # ===========================================
        # Cloud Providers
        # ===========================================

        # AWS
        (r"AKIA[0-9A-Z]{16}", "aws_access_key", Severity.CRITICAL),
        (r"ABIA[0-9A-Z]{16}", "aws_access_key", Severity.CRITICAL),
        (r"ACCA[0-9A-Z]{16}", "aws_access_key", Severity.CRITICAL),
        (r"ASIA[0-9A-Z]{16}", "aws_temp_access_key", Severity.CRITICAL),
        (r"(?:aws|amazon).{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]", "aws_secret_key", Severity.CRITICAL),

        # Azure
        (r"(?:AccountKey|account_key|storage_key|storageKey)\s*[=:]\s*['\"]?([a-zA-Z0-9+/]{86}==)", "azure_storage_key", Severity.HIGH),
        (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", "azure_connection_string", Severity.CRITICAL),

        # Google Cloud
        (r"AIza[0-9A-Za-z_-]{35}", "google_api_key", Severity.HIGH),
        (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "google_oauth_client", Severity.HIGH),
        (r"ya29\.[0-9A-Za-z_-]+", "google_oauth_token", Severity.HIGH),
        (r'"type"\s*:\s*"service_account"', "google_service_account", Severity.HIGH),

        # DigitalOcean
        (r"dop_v1_[a-f0-9]{64}", "digitalocean_pat", Severity.HIGH),
        (r"doo_v1_[a-f0-9]{64}", "digitalocean_oauth", Severity.HIGH),
        (r"dor_v1_[a-f0-9]{64}", "digitalocean_refresh", Severity.HIGH),

        # ===========================================
        # AI/ML Services
        # ===========================================

        # OpenAI
        (r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", "openai_api_key", Severity.CRITICAL),
        (r"sk-proj-[a-zA-Z0-9_-]{48,}", "openai_project_key", Severity.CRITICAL),
        (r"sk-[a-zA-Z0-9]{48,}", "openai_api_key", Severity.CRITICAL),

        # Anthropic (Claude)
        (r"sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{93}", "anthropic_api_key", Severity.CRITICAL),

        # Hugging Face
        (r"hf_[a-zA-Z0-9]{34}", "huggingface_token", Severity.HIGH),

        # Replicate
        (r"r8_[a-zA-Z0-9]{40}", "replicate_api_key", Severity.HIGH),

        # ===========================================
        # Version Control & CI/CD
        # ===========================================

        # GitHub
        (r"ghp_[0-9a-zA-Z]{36}", "github_pat", Severity.CRITICAL),
        (r"gho_[0-9a-zA-Z]{36}", "github_oauth", Severity.CRITICAL),
        (r"ghu_[0-9a-zA-Z]{36}", "github_user_token", Severity.HIGH),
        (r"ghs_[0-9a-zA-Z]{36}", "github_server_token", Severity.HIGH),
        (r"ghr_[0-9a-zA-Z]{36}", "github_refresh_token", Severity.HIGH),
        (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "github_fine_grained_pat", Severity.CRITICAL),

        # GitLab
        (r"glpat-[0-9a-zA-Z_-]{20}", "gitlab_pat", Severity.CRITICAL),
        (r"glptt-[0-9a-f]{40}", "gitlab_pipeline_token", Severity.HIGH),
        (r"GR1348941[0-9a-zA-Z_-]{20}", "gitlab_runner_token", Severity.HIGH),

        # Bitbucket
        (r"ATBB[a-zA-Z0-9]{32}", "bitbucket_app_password", Severity.HIGH),

        # NPM
        (r"npm_[a-zA-Z0-9]{36}", "npm_access_token", Severity.HIGH),

        # PyPI
        (r"pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}", "pypi_api_token", Severity.HIGH),

        # Vercel
        (r"vercel_[a-zA-Z0-9]{24,}", "vercel_token", Severity.HIGH),

        # CircleCI
        (r"circle-token\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?", "circleci_token", Severity.HIGH),

        # Travis CI
        (r"travis\s*[:=]\s*['\"]?([a-zA-Z0-9]{22})['\"]?", "travis_token", Severity.HIGH),

        # ===========================================
        # Payment Providers
        # ===========================================

        # Stripe
        (r"sk_live_[0-9a-zA-Z]{24,}", "stripe_secret_key", Severity.CRITICAL),
        (r"sk_test_[0-9a-zA-Z]{24,}", "stripe_test_key", Severity.MEDIUM),
        (r"pk_live_[0-9a-zA-Z]{24,}", "stripe_publishable_key", Severity.MEDIUM),
        (r"rk_live_[0-9a-zA-Z]{24,}", "stripe_restricted_key", Severity.HIGH),
        (r"whsec_[a-zA-Z0-9]{32,}", "stripe_webhook_secret", Severity.HIGH),

        # Square
        (r"sq0atp-[0-9A-Za-z_-]{22}", "square_access_token", Severity.CRITICAL),
        (r"sq0csp-[0-9A-Za-z_-]{43}", "square_oauth_secret", Severity.CRITICAL),
        (r"EAAAE[a-zA-Z0-9]{59}", "square_sandbox_token", Severity.MEDIUM),

        # PayPal
        (r"access_token\$production\$[a-z0-9]{13}\$[a-f0-9]{32}", "paypal_access_token", Severity.CRITICAL),
        (r"A21AA[a-zA-Z0-9_-]{60,}", "paypal_client_secret", Severity.HIGH),

        # Shopify
        (r"shpat_[a-fA-F0-9]{32}", "shopify_access_token", Severity.HIGH),
        (r"shpca_[a-fA-F0-9]{32}", "shopify_custom_app_token", Severity.HIGH),
        (r"shppa_[a-fA-F0-9]{32}", "shopify_private_app_token", Severity.HIGH),
        (r"shpss_[a-fA-F0-9]{32}", "shopify_shared_secret", Severity.HIGH),

        # ===========================================
        # Communication Services
        # ===========================================

        # Twilio
        (r"\bSK[0-9a-fA-F]{32}\b", "twilio_api_key", Severity.HIGH),
        (r"\bAC[a-zA-Z0-9]{32}\b", "twilio_account_sid", Severity.MEDIUM),

        # Slack
        (r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}", "slack_token", Severity.HIGH),
        (r"xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24,}", "slack_token", Severity.HIGH),
        (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "slack_webhook", Severity.HIGH),

        # Discord
        (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "discord_bot_token", Severity.CRITICAL),
        (r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", "discord_webhook", Severity.HIGH),

        # Telegram
        (r"[0-9]+:AA[0-9A-Za-z_-]{33}", "telegram_bot_token", Severity.HIGH),

        # SendGrid
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "sendgrid_api_key", Severity.HIGH),

        # Mailgun
        (r"(?<![0-9A-Za-z_-])key-[0-9a-zA-Z]{32}(?![0-9A-Za-z_-])", "mailgun_api_key", Severity.HIGH),
        (r"(?<![0-9a-f])[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}(?![0-9a-f-])", "mailgun_private_key", Severity.HIGH),

        # Mailchimp
        (r"[a-f0-9]{32}-us[0-9]{1,2}", "mailchimp_api_key", Severity.HIGH),

        # ===========================================
        # Database & Backend Services
        # ===========================================

        # Firebase
        (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "firebase_cloud_messaging", Severity.HIGH),
        (r"[a-zA-Z0-9_-]+\.firebaseio\.com", "firebase_database_url", Severity.MEDIUM),
        (r"[a-zA-Z0-9_-]+\.firebasestorage\.googleapis\.com", "firebase_storage_url", Severity.MEDIUM),

        # Supabase
        (r"sbp_[a-f0-9]{40}", "supabase_service_key", Severity.CRITICAL),
        # Note: the generic HS256 JWT header (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9) is not
        # Supabase-specific; generic JWTs are caught by the jwt_token pattern below.

        # MongoDB
        (r"mongodb\+srv://[^:]+:[^@]+@[^/]+", "mongodb_connection_string", Severity.CRITICAL),
        (r"mongodb://[^:]+:[^@]+@[^/]+", "mongodb_connection_string", Severity.CRITICAL),

        # PostgreSQL
        (r"postgres://[^:]+:[^@]+@[^/]+", "postgres_connection_string", Severity.CRITICAL),
        (r"postgresql://[^:]+:[^@]+@[^/]+", "postgres_connection_string", Severity.CRITICAL),

        # MySQL
        (r"mysql://[^:]+:[^@]+@[^/]+", "mysql_connection_string", Severity.CRITICAL),

        # Redis
        (r"redis://[^:]+:[^@]+@[^/]+", "redis_connection_string", Severity.CRITICAL),
        (r"rediss://[^:]+:[^@]+@[^/]+", "redis_connection_string", Severity.CRITICAL),

        # PlanetScale
        (r"pscale_tkn_[a-zA-Z0-9_-]{43}", "planetscale_token", Severity.HIGH),
        (r"pscale_pw_[a-zA-Z0-9_-]{43}", "planetscale_password", Severity.CRITICAL),

        # ===========================================
        # Monitoring & Analytics
        # ===========================================

        # New Relic
        (r"NRAK-[A-Z0-9]{27}", "newrelic_user_key", Severity.HIGH),
        (r"NRJS-[a-f0-9]{19}", "newrelic_browser_key", Severity.MEDIUM),

        # Sentry
        (r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+", "sentry_dsn", Severity.MEDIUM),
        (r"sntrys_[a-zA-Z0-9]{64}", "sentry_auth_token", Severity.HIGH),

        # ===========================================
        # CDN & Infrastructure
        # ===========================================

        # Cloudflare
        (r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}", "cloudflare_api_token", Severity.HIGH),

        # ===========================================
        # Productivity & Collaboration
        # ===========================================

        # Linear
        (r"lin_api_[a-zA-Z0-9]{40}", "linear_api_key", Severity.HIGH),

        # Notion
        (r"secret_[a-zA-Z0-9]{43}", "notion_integration_token", Severity.HIGH),
        (r"ntn_[a-zA-Z0-9]{50,}", "notion_token", Severity.HIGH),

        # Airtable (must be exactly 17 chars and not part of a longer identifier)
        (r"(?<![a-zA-Z0-9_])key[a-zA-Z0-9]{14}(?![a-zA-Z0-9_])", "airtable_api_key", Severity.HIGH),
        (r"pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}", "airtable_pat", Severity.HIGH),

        # Asana
        (r"[0-9]/[0-9]{16}:[a-zA-Z0-9]{32}", "asana_pat", Severity.HIGH),

        # Figma
        (r"figd_[a-zA-Z0-9_-]{40,}", "figma_pat", Severity.HIGH),

        # ===========================================
        # Auth & Security
        # ===========================================

        # JWT (generic)
        (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt_token", Severity.MEDIUM),

        # Auth0
        (r"[a-zA-Z0-9_-]{32,}\.auth0\.com", "auth0_domain", Severity.MEDIUM),

        # Okta
        (r"(?:okta|SSWS)\s*[:=]\s*['\"]?(00[a-zA-Z0-9]{40})['\"]?", "okta_api_token", Severity.HIGH),

        # Private keys (PEM format)
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", Severity.CRITICAL),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", Severity.CRITICAL),

        # SSH Keys
        (r"ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}", "ssh_public_key", Severity.LOW),
        (r"ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}", "ssh_public_key", Severity.LOW),

        # Database URLs (additional)
        (r"(?:mongodb|postgres|mysql|redis|amqp|rabbitmq)://[^'\"\s]+:[^'\"\s]+@[^'\"\s]+", "database_url", Severity.CRITICAL),
    ]

    # Generic assignment-context patterns (scanned against source content, not string literals)
    GENERIC_PATTERNS = [
        (r"['\"]?(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "api_key", Severity.HIGH, Confidence.HIGH),
        (r"['\"]?(?:secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "secret_key", Severity.HIGH, Confidence.HIGH),
        (r"['\"]?(?:session(?:[_-]?(?:id|token|key))?|sess(?:ion|id)?|jsessionid|phpsessid|connect\.sid|nextauth\.session-token|next-auth\.session-token|session_cookie|cookie_token)['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "session_token", Severity.MEDIUM, Confidence.MEDIUM),
        (r"['\"]?(?:access[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "access_token", Severity.HIGH, Confidence.HIGH),
        (r"['\"]?(?:auth[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "auth_token", Severity.HIGH, Confidence.HIGH),
        (r"['\"]?(?:secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "generic_secret", Severity.MEDIUM, Confidence.HIGH),
        (r"['\"]?(?:auth|authorization)['\"]?\s*[:=]\s*['\"](?:Bearer |Basic )?([a-zA-Z0-9_.-]{20,})['\"]", "auth_header", Severity.MEDIUM, Confidence.MEDIUM),
    ]

    # Exclude patterns (placeholder, test values)
    EXCLUDE_PATTERNS = [
        r"^your[-_]?(api[-_]?)?(key|token|secret)",  # your-api-key-here
        r"^xxx+",
        r".*placeholder",  # Contains placeholder anywhere
        r"^example",
        r"^test[-_]?(key|token|secret|api|value)",  # test_key, test_token, etc.
        r"^sample",
        r"^demo",
        r"^fake",
        r"^dummy",
        r"^\$\{.+\}$",  # Template variables
        r"^<.+>$",  # Placeholder brackets
        r"^process\.env\.",
        r"^import\.meta\.env\.",
        r"^ENV\[",
        r".*[-_]here$",  # Ends with -here (placeholder)
        r"^insert[-_]",  # insert-your-key
        r"^replace[-_]",  # replace-with-key
    ]

    SESSION_CONTEXT_PATTERN = re.compile(
        r"(?:session(?:[_-]?(?:id|token|key))?|sess(?:ion|id)?|jsessionid|phpsessid|"
        r"connect\.sid|nextauth\.session-token|next-auth\.session-token|"
        r"session_cookie|cookie_token|cookie)",
        re.IGNORECASE,
    )

    def __init__(self, entropy_threshold: float = 3.5):
        self.entropy_threshold = entropy_threshold

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match secrets in IR."""
        seen_literal_values = set()
        emitted_values = set()
        entropy_candidates = []

        for literal in ir.string_literals:
            value = literal.value

            # Skip short strings
            if len(value) < 8:
                continue

            # Skip duplicates
            if value in seen_literal_values:
                continue
            seen_literal_values.add(value)

            # Skip excluded patterns
            if self._is_excluded(value):
                continue

            # Check known patterns
            for pattern, secret_type, severity in self.SECRET_PATTERNS:
                match = re.search(pattern, value)
                if match:
                    matched_value = match.group(0)
                    if len(match.groups()) > 0:
                        matched_value = match.group(1)

                    effective_secret_type = secret_type
                    effective_severity = severity
                    effective_confidence = Confidence.HIGH
                    context_override = self._session_context_override(
                        secret_type=secret_type,
                        literal_line=literal.line,
                        source_content=context.source_content or "",
                    )
                    if context_override:
                        effective_secret_type = context_override["value_type"]
                        effective_severity = context_override["severity"]
                        effective_confidence = context_override["confidence"]

                    # Prevent duplicate from GENERIC_PATTERNS scan
                    emitted_values.add(matched_value)

                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=effective_severity,
                        confidence=effective_confidence,
                        title=f"Hardcoded {effective_secret_type.replace('_', ' ').title()}",
                        description=f"Found hardcoded {effective_secret_type} in source code",
                        extracted_value=matched_value,
                        value_type=effective_secret_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        tags=["secret", effective_secret_type],
                        metadata={
                            "matched_text": match.group(0),
                            "match_uses_capture_group": len(match.groups()) > 0 and matched_value != match.group(0),
                            "matched_pattern_type": secret_type,
                            "contextual_type_override": (
                                effective_secret_type if effective_secret_type != secret_type else None
                            ),
                        },
                    )
                    break
            else:
                entropy_candidates.append((value, literal))

        # Scan source content for generic assignment-context patterns
        if context.source_content:
            for pattern, secret_type, severity, confidence in self.GENERIC_PATTERNS:
                for match in re.finditer(pattern, context.source_content, re.IGNORECASE):
                    matched_value = match.group(0)
                    if len(match.groups()) > 0:
                        matched_value = match.group(1)

                    if self._is_excluded(matched_value):
                        continue

                    if matched_value in emitted_values:
                        continue
                    emitted_values.add(matched_value)

                    line = context.source_content[:match.start()].count("\n") + 1
                    line_start = context.source_content.rfind("\n", 0, match.start()) + 1
                    column = match.start() - line_start

                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=severity,
                        confidence=confidence,
                        title=f"Hardcoded {secret_type.replace('_', ' ').title()}",
                        description=f"Found hardcoded {secret_type} in source code",
                        extracted_value=matched_value,
                        value_type=secret_type,
                        line=line,
                        column=column,
                        ast_node_type="Expression",
                        tags=["secret", secret_type],
                        metadata={
                            "matched_text": match.group(0),
                            "match_uses_capture_group": len(match.groups()) > 0 and matched_value != match.group(0),
                            "match_column": column,
                        },
                    )

        for value, literal in entropy_candidates:
            if value in emitted_values:
                continue
            if not self._looks_like_secret(value) or not self._is_high_quality_random(value):
                continue

            entropy = self._calculate_entropy(value)
            normalized = self._calculate_normalized_entropy(value)
            bigram = self._calculate_bigram_entropy(value)
            diversity = self._calculate_char_class_diversity(value)

            confidence = Confidence.LOW
            if normalized > 0.85 and diversity >= 3:
                confidence = Confidence.MEDIUM
            if normalized > 0.9 and bigram > 3.0 and diversity >= 3:
                confidence = Confidence.HIGH

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=confidence,
                title="Potential Hardcoded Secret",
                description=f"High-entropy string found (entropy: {entropy:.2f}, normalized: {normalized:.2f})",
                extracted_value=value,
                value_type="potential_secret",
                line=literal.line,
                column=literal.column,
                ast_node_type="Literal",
                tags=["secret", "entropy"],
                metadata={
                    "entropy": entropy,
                    "normalized_entropy": normalized,
                    "bigram_entropy": bigram,
                    "char_class_diversity": diversity,
                },
            )
            emitted_values.add(value)

    def _is_excluded(self, value: str) -> bool:
        """Check if value matches exclusion patterns."""
        for pattern in self.EXCLUDE_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        # Exclude common false positives
        if value.startswith("http://") or value.startswith("https://"):
            # URLs without credentials are not secrets, unless they
            # contain credential-like query parameters
            if "@" not in value:
                credential_params = ("key=", "token=", "secret=", "password=",
                                     "auth=", "api_key=", "apikey=", "access_token=")
                if not any(kw in value.lower() for kw in credential_params):
                    return True

        # Exclude file paths
        if value.startswith("/") and "/" in value[1:]:
            if not any(kw in value.lower() for kw in ["secret", "key", "token", "pass"]):
                return True

        return False

    def _session_context_override(
        self,
        *,
        secret_type: str,
        literal_line: int,
        source_content: str,
    ) -> dict[str, object] | None:
        """Downgrade session-like literals found in explicit session/cookie assignment context."""
        if secret_type not in {"jwt_token", "access_token"}:
            return None
        if literal_line <= 0 or not source_content:
            return None

        line_text = self._source_line(source_content, literal_line)
        if not line_text:
            return None
        if not self.SESSION_CONTEXT_PATTERN.search(line_text):
            return None

        return {
            "value_type": "session_token",
            "severity": Severity.MEDIUM,
            "confidence": Confidence.MEDIUM,
        }

    def _source_line(self, source_content: str, line_number: int) -> str:
        """Return a single source line using 1-based line numbers."""
        if line_number <= 0:
            return ""
        lines = source_content.splitlines()
        index = line_number - 1
        if index >= len(lines):
            return ""
        return lines[index]

    def _looks_like_secret(self, value: str) -> bool:
        """
        Check if string looks like a secret using multiple heuristics.

        Uses character class diversity, structure analysis, and
        pattern recognition to identify potential secrets.
        """
        # Must have sufficient length
        if len(value) < 16:
            return False

        # Shouldn't look like a word or path
        if " " in value:
            return False

        # Check character class diversity
        diversity = self._calculate_char_class_diversity(value)
        if diversity < 2:
            return False

        # Check for common non-secret patterns
        if self._is_common_non_secret(value):
            return False

        # Check for base64-like pattern
        if re.match(r"^[A-Za-z0-9+/=_-]+$", value):
            return True

        # Check for hex pattern
        if re.match(r"^[0-9a-fA-F]+$", value):
            return len(value) >= 32

        return True

    def _calculate_char_class_diversity(self, value: str) -> int:
        """
        Calculate number of distinct character classes in string.

        Returns count of: uppercase, lowercase, digits, special chars
        """
        classes = 0
        if any(c.isupper() for c in value):
            classes += 1
        if any(c.islower() for c in value):
            classes += 1
        if any(c.isdigit() for c in value):
            classes += 1
        if any(not c.isalnum() for c in value):
            classes += 1
        return classes

    def _is_common_non_secret(self, value: str) -> bool:
        """Check if value is a common non-secret pattern."""
        # Common hash/ID formats that aren't secrets
        non_secret_patterns = [
            # Git commit hashes (40 hex chars)
            r"^[0-9a-f]{40}$",
            # Short git hashes
            r"^[0-9a-f]{7,8}$",
            # Common version strings
            r"^v?\d+\.\d+\.\d+",
            # Date-like strings
            r"^\d{4}-\d{2}-\d{2}",
            # Common build identifiers
            r"^build[_-]?[0-9a-f]+$",
            # CSS class names
            r"^[a-z]+(-[a-z0-9]+)+$",
            # Webpack chunk names
            r"^(chunk|vendors|main|runtime)[~\-.]",
        ]

        for pattern in non_secret_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        return False

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0

        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(value)
            entropy -= p * math.log2(p)

        return entropy

    def _calculate_normalized_entropy(self, value: str) -> float:
        """
        Calculate normalized entropy (bits per character).

        Normalized entropy is useful for comparing strings of different lengths.
        Maximum theoretical entropy for printable ASCII is about 6.57 bits.
        """
        if not value:
            return 0.0

        entropy = self._calculate_entropy(value)

        # Normalize by maximum possible entropy
        unique_chars = len(set(value))
        if unique_chars <= 1:
            return 0.0

        max_entropy = math.log2(unique_chars)
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def _calculate_bigram_entropy(self, value: str) -> float:
        """
        Calculate entropy based on character bigrams.

        This helps detect patterns in randomness - true random strings
        should have high bigram entropy, while passwords with patterns
        (like 'Password123!') will have lower bigram entropy.
        """
        if len(value) < 3:
            return 0.0

        bigrams = [value[i:i+2] for i in range(len(value) - 1)]

        freq = {}
        for bg in bigrams:
            freq[bg] = freq.get(bg, 0) + 1

        entropy = 0.0
        total = len(bigrams)
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    def _is_high_quality_random(self, value: str) -> bool:
        """
        Check if a string appears to be high-quality random data.

        Uses multiple entropy metrics to distinguish true secrets
        from low-quality random strings or patterns.
        """
        # Basic entropy check
        basic_entropy = self._calculate_entropy(value)
        if basic_entropy < self.entropy_threshold:
            return False

        # Normalized entropy should be high (> 0.8)
        normalized = self._calculate_normalized_entropy(value)
        if normalized < 0.75:
            return False

        # For longer strings, check bigram entropy
        if len(value) >= 20:
            bigram_entropy = self._calculate_bigram_entropy(value)
            # Bigram entropy should be at least 2.0 for quality randomness
            if bigram_entropy < 2.0:
                return False

        # Check for repetitive patterns
        if self._has_repetitive_pattern(value):
            return False

        return True

    def _has_repetitive_pattern(self, value: str) -> bool:
        """Check if string contains repetitive patterns."""
        # Check for repeating substrings
        length = len(value)

        for pattern_len in range(1, min(length // 2 + 1, 16)):
            pattern = value[:pattern_len]
            repeated = pattern * (length // pattern_len + 1)
            if repeated[:length] == value:
                return True

        # Check for common repeating patterns
        for pattern in ['123', 'abc', 'xyz', '000', 'aaa']:
            if pattern * 3 in value.lower():
                return True

        return False

