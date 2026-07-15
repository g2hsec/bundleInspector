"""
Secret detector.

Detects hardcoded secrets, API keys, tokens, and credentials.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from typing import TypedDict

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)


def _extract_required_prefix(pattern: str) -> str | None:
    """
    Return a leading literal substring that MUST appear in any match of `pattern`,
    or None if one cannot be soundly determined.

    Used as a cheap, exact pre-filter for the secret-pattern loop: if the required
    literal is absent from a candidate string, the pattern cannot possibly match, so
    it is skipped. Only a contiguous run of leading top-level LITERAL characters is
    collected, after skipping leading zero-width assertions (`^`, `\\b`, lookarounds).
    Quantified/optional/class/alternation constructs stop collection, so the prefix is
    always mandatory (never optional) and skipping on its absence never drops a match.
    Any parsing difficulty yields None (the pattern then always runs).
    """
    try:
        parser = re.__dict__.get("_parser")
        if parser is None:
            return None
        parsed = parser.parse(pattern)
    except Exception:
        return None
    chars: list[str] = []
    started = False
    for op, av in parsed:
        name = getattr(op, "name", str(op))
        if name == "LITERAL":
            try:
                chars.append(chr(av))
            except (ValueError, TypeError):
                break
            started = True
        elif name in ("AT", "ASSERT", "ASSERT_NOT") and not started:
            continue  # leading zero-width assertion: following literals stay mandatory
        else:
            break
    return "".join(chars) if chars else None


class _SessionOverride(TypedDict):
    value_type: str
    severity: Severity
    confidence: Confidence


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
        (
            r"(?:aws|amazon).{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]",
            "aws_secret_key",
            Severity.CRITICAL,
        ),
        # Azure
        (
            r"(?:AccountKey|account_key|storage_key|storageKey)\s*[=:]\s*['\"]?([a-zA-Z0-9+/]{86}==)",
            "azure_storage_key",
            Severity.HIGH,
        ),
        (
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
            "azure_connection_string",
            Severity.CRITICAL,
        ),
        # Google Cloud
        (r"AIza[0-9A-Za-z_-]{35}", "google_api_key", Severity.HIGH),
        (
            r"[0-9]{1,64}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "google_oauth_client",
            Severity.HIGH,
        ),
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
        (
            r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
            "github_fine_grained_pat",
            Severity.CRITICAL,
        ),
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
        (
            r"access_token\$production\$[a-z0-9]{13}\$[a-f0-9]{32}",
            "paypal_access_token",
            Severity.CRITICAL,
        ),
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
        (
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "slack_webhook",
            Severity.HIGH,
        ),
        # Discord
        (r"[MN][A-Za-z\d]{23,40}\.[\w-]{6}\.[\w-]{27}", "discord_bot_token", Severity.CRITICAL),
        (
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "discord_webhook",
            Severity.HIGH,
        ),
        # Telegram
        (r"[0-9]{1,32}:AA[0-9A-Za-z_-]{33}", "telegram_bot_token", Severity.HIGH),
        # SendGrid
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "sendgrid_api_key", Severity.HIGH),
        # Mailgun
        (
            r"(?<![0-9A-Za-z_-])key-[0-9a-zA-Z]{32}(?![0-9A-Za-z_-])",
            "mailgun_api_key",
            Severity.HIGH,
        ),
        (
            r"(?<![0-9a-f])[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}(?![0-9a-f-])",
            "mailgun_private_key",
            Severity.HIGH,
        ),
        # Mailchimp
        (r"[a-f0-9]{32}-us[0-9]{1,2}", "mailchimp_api_key", Severity.HIGH),
        # ===========================================
        # Database & Backend Services
        # ===========================================
        # Firebase
        (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "firebase_cloud_messaging", Severity.HIGH),
        (r"[a-zA-Z0-9_-]{1,253}\.firebaseio\.com", "firebase_database_url", Severity.MEDIUM),
        (
            r"[a-zA-Z0-9_-]{1,253}\.firebasestorage\.googleapis\.com",
            "firebase_storage_url",
            Severity.MEDIUM,
        ),
        # Supabase
        (r"sbp_[a-f0-9]{40}", "supabase_service_key", Severity.CRITICAL),
        # Note: the generic HS256 JWT header (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9) is not
        # Supabase-specific; generic JWTs are caught by the jwt_token pattern below.
        # MongoDB
        (
            r"mongodb\+srv://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "mongodb_connection_string",
            Severity.CRITICAL,
        ),
        (
            r"mongodb://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "mongodb_connection_string",
            Severity.CRITICAL,
        ),
        # PostgreSQL
        (
            r"postgres://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "postgres_connection_string",
            Severity.CRITICAL,
        ),
        (
            r"postgresql://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "postgres_connection_string",
            Severity.CRITICAL,
        ),
        # MySQL
        (
            r"mysql://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "mysql_connection_string",
            Severity.CRITICAL,
        ),
        # Redis
        (
            r"redis://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "redis_connection_string",
            Severity.CRITICAL,
        ),
        (
            r"rediss://[^:]{1,256}:[^@]{1,256}@[^/]{1,512}",
            "redis_connection_string",
            Severity.CRITICAL,
        ),
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
        (
            r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
            "sentry_dsn",
            Severity.MEDIUM,
        ),
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
        (
            r"eyJ[A-Za-z0-9_-]{1,8192}\.eyJ[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,8192}",
            "jwt_token",
            Severity.MEDIUM,
        ),
        # Auth0
        (r"[a-zA-Z0-9_-]{32,253}\.auth0\.com", "auth0_domain", Severity.MEDIUM),
        # Okta
        (
            r"(?:okta|SSWS)\s*[:=]\s*['\"]?(00[a-zA-Z0-9]{40})['\"]?",
            "okta_api_token",
            Severity.HIGH,
        ),
        # Private keys (PEM format)
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "private_key",
            Severity.CRITICAL,
        ),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", Severity.CRITICAL),
        # SSH Keys
        (r"ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}", "ssh_public_key", Severity.LOW),
        (r"ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}", "ssh_public_key", Severity.LOW),
        # Database URLs (additional)
        (
            r"(?:mongodb|postgres|mysql|redis|amqp|rabbitmq)://[^'\"\s]{1,256}:[^'\"\s]{1,256}@[^'\"\s]{1,512}",
            "database_url",
            Severity.CRITICAL,
        ),
    ]

    # Generic assignment-context patterns (scanned against source content, not string literals)
    GENERIC_PATTERNS = [
        (
            r"['\"]?(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "api_key",
            Severity.HIGH,
            Confidence.HIGH,
        ),
        (
            r"['\"]?(?:secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "secret_key",
            Severity.HIGH,
            Confidence.HIGH,
        ),
        (
            r"['\"]?(?:session(?:[_-]?(?:id|token|key))?|sess(?:ion|id)?|jsessionid|phpsessid|connect\.sid|nextauth\.session-token|next-auth\.session-token|session_cookie|cookie_token)['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
            "session_token",
            Severity.MEDIUM,
            Confidence.MEDIUM,
        ),
        (
            r"['\"]?(?:access[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "access_token",
            Severity.HIGH,
            Confidence.HIGH,
        ),
        (
            r"['\"]?(?:auth[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "auth_token",
            Severity.HIGH,
            Confidence.HIGH,
        ),
        (
            r"['\"]?(?:secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "generic_secret",
            Severity.MEDIUM,
            Confidence.HIGH,
        ),
        (
            r"['\"]?(?:auth|authorization)['\"]?\s*[:=]\s*['\"](?:Bearer |Basic )?([a-zA-Z0-9_.-]{20,})['\"]",
            "auth_header",
            Severity.MEDIUM,
            Confidence.MEDIUM,
        ),
    ]

    # Precompiled patterns (perf). Each secret entry carries a sound required-literal
    # prefilter so most non-secret string literals skip the regex entirely. Compiled with
    # the SAME flags as the original call sites (SECRET: none/case-sensitive via re.search;
    # GENERIC: re.IGNORECASE via re.finditer) so matches are byte-identical.
    _COMPILED_SECRET_PATTERNS = [
        # Disable the required-literal prefilter for case-insensitive patterns: a
        # case-sensitive substring check could wrongly skip a case-varied match (FN).
        # No current pattern is IGNORECASE, so this only future-proofs the prefilter.
        (_cp, _t, _s, None if (_cp.flags & re.IGNORECASE) else _extract_required_prefix(_p))
        for (_p, _t, _s) in SECRET_PATTERNS
        for _cp in (re.compile(_p),)
    ]
    _COMPILED_GENERIC_PATTERNS = [
        (re.compile(_p, re.IGNORECASE), _t, _s, _c) for (_p, _t, _s, _c) in GENERIC_PATTERNS
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

    # Secret-related vocabulary; used to gate context-less entropy hits down to LOW.
    _SECRET_CONTEXT_LINE = re.compile(
        r"secret|token|key|password|passwd|pwd|auth|credential|apikey|bearer|"
        r"private|access[_-]?token|client[_-]?secret",
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
        emitted_occurrences: set[tuple[str, int]] = set()
        entropy_candidates = []

        for literal in ir.string_literals:
            value = literal.value

            # Skip short strings
            if len(value) < 8:
                continue

            # Skip excluded patterns
            if self._is_excluded(value):
                continue

            # Check known patterns (precompiled + sound required-literal prefilter)
            provider_match = False
            for pattern, secret_type, severity, required in self._COMPILED_SECRET_PATTERNS:
                if required is not None and required not in value:
                    continue
                for match in pattern.finditer(value):
                    provider_match = True
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

                    # Prevent a generic assignment matcher from duplicating this provider match on
                    # the same line while preserving independent occurrences on other lines.
                    emitted_occurrences.add((matched_value, literal.line))

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
                        column=literal.column + match.start(),
                        ast_node_type="Literal",
                        tags=["secret", effective_secret_type],
                        metadata={
                            "matched_text": match.group(0),
                            "match_uses_capture_group": len(match.groups()) > 0
                            and matched_value != match.group(0),
                            "matched_pattern_type": secret_type,
                            "contextual_type_override": (
                                effective_secret_type
                                if effective_secret_type != secret_type
                                else None
                            ),
                        },
                    )
            if not provider_match:
                entropy_candidates.append((value, literal))

        # Scan source content for generic assignment-context patterns
        if context.source_content:
            for pattern, secret_type, severity, confidence in self._COMPILED_GENERIC_PATTERNS:
                for match in pattern.finditer(context.source_content):
                    matched_value = match.group(0)
                    if len(match.groups()) > 0:
                        matched_value = match.group(1)

                    if self._is_excluded(matched_value):
                        continue

                    line = context.source_content[: match.start()].count("\n") + 1
                    if (matched_value, line) in emitted_occurrences:
                        continue
                    emitted_occurrences.add((matched_value, line))
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
                            "match_uses_capture_group": len(match.groups()) > 0
                            and matched_value != match.group(0),
                            "match_column": column,
                        },
                    )

        for value, literal in entropy_candidates:
            if (value, literal.line) in emitted_occurrences:
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

            tags = ["secret", "entropy"]
            metadata: dict[str, object] = {
                "entropy": entropy,
                "normalized_entropy": normalized,
                "bigram_entropy": bigram,
                "char_class_diversity": diversity,
            }
            # Context gate: demote (never drop) high-entropy blobs on lines without secret
            # vocabulary, so real credential-context secrets rank above bland random strings.
            if not self._line_has_secret_context(
                self._source_line(context.source_content or "", literal.line)
            ):
                confidence = Confidence.LOW
                tags.append("entropy-no-context")
                metadata["downgrade_reason"] = "no_secret_context"

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
                tags=tags,
                metadata=metadata,
            )
            emitted_occurrences.add((value, literal.line))

    def _is_excluded(self, value: str) -> bool:
        """Check if value matches exclusion patterns."""
        for pattern in self.EXCLUDE_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        # Exclude scheme URLs without embedded credentials -- re-reported by the Domain/
        # Endpoint detectors, never a secret. Credential-bearing URLs (token=, user:pass@)
        # keep the same guard so they still reach secret detection.
        credential_params = (
            "key=",
            "token=",
            "secret=",
            "password=",
            "auth=",
            "api_key=",
            "apikey=",
            "access_token=",
        )
        if value.startswith(("http://", "https://", "s3://", "gs://", "ws://", "wss://")):
            if "@" not in value and not any(kw in value.lower() for kw in credential_params):
                # Known webhook URLs carry their secret in the PATH (not a query credential), so they
                # are NOT generic scheme-URLs to drop -- let the webhook patterns run (DQ-S03).
                _low = value.lower()
                _webhook_markers = (
                    "hooks.slack.com/services/",
                    "discord.com/api/webhooks/",
                    "discordapp.com/api/webhooks/",
                )
                if not any(m in _low for m in _webhook_markers):
                    return True

        # Inline data: URIs (base64 assets/sourcemaps) are provably not credentials.
        if value.startswith("data:"):
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
    ) -> _SessionOverride | None:
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

    def _line_has_secret_context(self, line_text: str) -> bool:
        """True when the finding's line carries secret-related vocabulary (assignment context)."""
        return bool(line_text and self._SECRET_CONTEXT_LINE.search(line_text))

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

        # URL / endpoint path or a CSS/DOM selector -- reported by the endpoint/domain
        # detectors, and a common entropy false-positive class, not a secret.
        if self._is_url_or_selector(value):
            return False

        # Multi-word code identifier (camelCase / SCREAMING_SNAKE) made of common words --
        # a random opaque token scores ~0 word-coverage, so real secrets are unaffected.
        if self._is_dictionary_identifier(value):
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

    # Server-side endpoint extension (optionally followed by a query) and a query string of
    # key=value pairs -- URL/endpoint shapes, not secrets. A real opaque token (base64/hex) has
    # no dot-extension and no "?key=" query, so these never suppress a genuine secret.
    _RE_ENDPOINT_EXT = re.compile(
        r"\.(?:do|jsp|jspx|action|php|phtml|aspx|ashx|asmx|jsf|cgi)(?:\?|$)", re.IGNORECASE
    )
    _RE_QUERY_STRING = re.compile(r"[?&][A-Za-z_][\w.-]*=")

    def _is_url_or_selector(self, value: str) -> bool:
        """Return True for URL/endpoint paths and CSS/DOM selectors (not secrets)."""
        # CSS / DOM selector (class, id, attribute, pseudo-class).
        if value[:1] in ".#[:":
            return True
        # Server-side endpoint path (.do/.jsp/...) or a key=value query string.
        if self._RE_ENDPOINT_EXT.search(value) or self._RE_QUERY_STRING.search(value):
            return True
        return False

    # Common English + web/UI/e-commerce words used to recognize multi-word CODE IDENTIFIERS
    # (camelCase / SCREAMING_SNAKE) that the entropy heuristic otherwise flags as secrets. A
    # random opaque token (base64/hex/api-key) tokenizes into NON-word segments -> ~0 coverage,
    # so genuine secrets are never suppressed by this filter (empirically 0 FN on a real-secret
    # battery; identifiers score >=0.70, secrets <=0.21).
    _COMMON_WORDS = frozenset(
        """
the and for are but not you all can has was one our out get use new now way each which their
time will about would there could other after first also some what when your from they know want
been good much more most over such only into than them then these list item view page data name
type code text link user role edit save load send open close click show hide next prev back home
main menu nav head header foot footer side title body content search result filter sort order
cart cash card coupon download upload notify prefer request response error success message
confirm cancel submit change detail details delete remove create update select option popup pop
modal dialog button input label field value check valid invalid login logout signin signup password
account member profile address receiver payment deliver delivery goods good product products
review comment rating star image photo file files before after already exceeded limit count
total price amount number step ref msg btn img src url api crit restock stock wish event guide
agent receipt claim refund group ecard preview enlarge zoom toggle class bool boolean string
array object index window frame form info method function return null default handler http name
paymentchange previous order cancel confirm claim prefer detail notify request receipt card cash
""".split()
    )

    def _identifier_word_coverage(self, value: str) -> float:
        """Fraction of a value's letters that belong to common-word segments (camelCase /
        SCREAMING_SNAKE tokenization). ~1.0 for word identifiers, ~0.0 for opaque tokens."""
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
            return 0.0
        tokens = [t for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+", value) if t]
        if len(tokens) < 2:
            return 0.0
        alpha_total = sum(len(t) for t in tokens)
        if not alpha_total:
            return 0.0
        covered = sum(len(t) for t in tokens if t.lower() in self._COMMON_WORDS)
        return covered / alpha_total

    def _is_dictionary_identifier(self, value: str) -> bool:
        """Multi-word camelCase / SCREAMING_SNAKE code identifier (e.g. loginPwBeforePopup,
        COUPON_DOWNLOAD_LIMIT_EXCEEDED), not a secret."""
        return len(value) <= 48 and self._identifier_word_coverage(value) >= 0.70

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
            # Common version strings (END-anchored so a secret merely STARTING with a version is not
            # excluded -- DQ-S05). Allow REPEATED dot/dash/plus pre-release+build segments so real
            # multi-segment SemVer (15.0.0-canary.abc, 1.2.3+sha.5114f85) stays excluded, while a
            # version-PREFIXED secret with no separator (1.2.3abcdef...) is NOT excluded.
            r"^v?\d+\.\d+\.\d+(?:[.+-][0-9A-Za-z]+)*$",
            # Date-like strings (END-anchored, optional ISO time/zone suffix)
            r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?(?:Z|[+-]\d{2}:?\d{2})?$",
            # Common build identifiers
            r"^build[_-]?[0-9a-f]+$",
            # CSS class names
            r"^[a-z]+(-[a-z0-9]+)+$",
            # Webpack chunk names
            r"^(chunk|vendors|main|runtime)[~\-.]",
            # Valid dotted DNS hostname, optional :port (always re-reported by DomainDetector,
            # never a secret) -- e.g. sso.example.com or sso.example.com:8070
            r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d+)?$",
            # Webpack/content-hash asset filename (e.g. app.4f3c2b1a.chunk.js)
            r"^[a-z0-9_.-]+\.[0-9a-f]{6,}\.(?:js|mjs|cjs|css|map|chunk\.js)$",
            # 4+ segment lowercase dotted namespace / i18n key (no hex/secret structure)
            r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){3,}$",
            # 2+ delimited key=value pairs: window.open feature specs
            # ("width=430,height=317,scrollbars=no"), query strings ("a=1&b=2&c=3"), inline
            # style specs -- structured config, not an opaque secret token. An optional leading
            # delimiter handles concatenation tails (",resizable=no,scrollbars=no,status=no").
            # A single "key=value" is NOT filtered (that could be "token=<secret>").
            r"^[,;&]?\s*[A-Za-z_][\w.-]*=[^=&,;]*(?:[,;&]\s*[A-Za-z_][\w.-]*=[^=&,;]*)+$",
            # 4+ pipe-separated identifier tokens: a minifier reserved-word list
            # ("null|httpRequest|function|return|if|var|GET|..."), never a secret.
            r"^[A-Za-z_$][\w$]*(?:\|[A-Za-z_$][\w$]*){3,}$",
        ]

        for pattern in non_secret_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        return False

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0

        freq: dict[str, int] = {}
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

        bigrams = [value[i : i + 2] for i in range(len(value) - 1)]

        freq: dict[str, int] = {}
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
        for pattern in ["123", "abc", "xyz", "000", "aaa"]:
            if pattern * 3 in value.lower():
                return True

        return False
