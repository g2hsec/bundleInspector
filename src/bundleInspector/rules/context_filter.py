"""
Context-based false positive filter.

Analyzes surrounding code context to reduce false positives
in secret and other detection rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bundleInspector.core.url_utils import safe_urlsplit as urlsplit
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Finding,
    IntermediateRepresentation,
    Severity,
)

# Severity ordering: higher index = more severe
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CONFIDENCE_ORDER = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}

# Low-structure heuristic secret value_types -- assignment-context matches (SecretDetector
# GENERIC_PATTERNS) and the entropy path ("potential_secret"). These may still be hard-dropped as
# FPs by the context filter. Everything else in Category.SECRET is a NAMED provider match and is
# protected from the hard drop (DQ-C01). Mirrors SecretDetector.GENERIC_PATTERNS value_types.
_GENERIC_SECRET_VALUE_TYPES = frozenset(
    {
        "potential_secret",
        "generic_secret",
        "api_key",
        "secret_key",
        "session_token",
        "access_token",
        "auth_token",
        "auth_header",
    }
)


@dataclass
class ContextSignal:
    """A context signal that affects confidence."""

    name: str
    is_false_positive: bool
    confidence_adjustment: float  # -1.0 to +1.0
    reason: str


# String-literal mask for the doc-context heuristic (compiled once). Disjoint alternatives
# (`(?!\1)[^\\]` vs `\\.`) keep it linear -- an overlapping bare `.` is exponential on a backslash run.
_DOC_MASK_RE = re.compile(r"""(["\'`])(?:\\.|(?!\1)[^\\])*\1""")
# Compiled once: the example/sample/demo line marker used by _check_line_context.
_EXAMPLE_LINE_RE = re.compile(r"@example\b|\b(example|sample|demo)\s*:", re.IGNORECASE)
_CONSOLE_CALL_RE = re.compile(r"console\.\w+\s*\(")
_UNSET = object()  # sentinel: distinguishes "not cached" from a cached None result


class ContextFilter:
    """
    Filter findings based on surrounding code context.

    Reduces false positives by analyzing:
    - Variable names (uuid, hash, version -> likely not secrets)
    - Assignment context (is the value assigned to a known non-secret var)
    - File context (test files, mock data, example configs)
    - Structural patterns (arrays of similar values, lookup tables)
    - Duplicate detection (same value across multiple patterns)
    """

    # Variable names that indicate non-secret values
    NON_SECRET_VAR_NAMES = {
        "uuid",
        "guid",
        "id",
        "uid",
        "objectid",
        "hash",
        "checksum",
        "digest",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "version",
        "ver",
        "revision",
        "rev",
        "timestamp",
        "time",
        "date",
        "created",
        "updated",
        "expires",
        "nonce",
        "salt",
        "iv",
        "color",
        "colour",
        "hex",
        "regex",
        "pattern",
        "regexp",
        "classname",
        "classnames",
        "css",
        "style",
        "mimetype",
        "contenttype",
        "encoding",
        "charset",
        "locale",
        "lang",
        "language",
        "timezone",
        "placeholder",
        "example",
        "sample",
        "demo",
        "test",
        "mock",
        "doc",
        "docs",
        "readme",
        "documentation",
        "guide",
        "tutorial",
        "snippet",
        "default",
        "fallback",
        "name",
        "label",
        "title",
        "description",
        "text",
        "message",
        "path",
        "route",
        "pathname",
        "dirname",
        "filename",
        "type",
        "kind",
        "category",
        "status",
        "state",
        "format",
        "template",
        "layout",
    }

    # File path patterns indicating test/mock context
    TEST_FILE_PATTERNS = [
        r"[/\\]tests?[/\\]",
        r"[/\\]__tests__[/\\]",
        r"[/\\]spec[/\\]",
        r"[/\\]__mocks__[/\\]",
        r"[/\\]fixtures?[/\\]",
        r"[/\\]stubs?[/\\]",
        r"\.test\.",
        r"\.spec\.",
        r"\.mock\.",
        r"\.example\.",
        r"\.sample\.",
    ]

    # String patterns that look like non-secret structured data
    NON_SECRET_VALUE_PATTERNS = [
        # CSS-like hex colors
        r"^#[0-9a-fA-F]{3,8}$",
        # Semantic version strings (anchored: unanchored "^\d+\.\d+\.\d+" also
        # matched — and silently dropped — real secrets that merely START with
        # digit.digit.digit, e.g. "12.34.5678deadbeefcafe"). Allow repeated
        # dot/dash/plus pre-release+build segments so real multi-segment SemVer
        # (1.2.3-canary.abc, 1.2.3+sha.5114f85) stays excluded (DQ-S05).
        r"^v?\d+\.\d+\.\d+(?:[.+-][0-9A-Za-z]+)*$",
        # ISO date strings (END-anchored so a secret merely STARTING with a date is not dropped --
        # DQ-S05; optional ISO time/zone suffix stays excluded)
        r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?(?:Z|[+-]\d{2}:?\d{2})?$",
        # Email addresses (not secrets themselves)
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        # MIME types
        r"^(application|text|image|audio|video|multipart)/[a-z0-9.+-]+$",
        # File extensions
        r"^\.[a-z]{2,5}$",
        # Simple word-based strings (spaces, natural language)
        r"^[a-zA-Z]+(\s[a-zA-Z]+){2,}$",
        # CSS class names (kebab-case with multiple segments)
        r"^[a-z][a-z0-9]*(-[a-z0-9]+){2,}$",
        # URL paths without credentials or credential-like query params
        r"^https?://[a-zA-Z0-9.-]+(?::\d+)?(/[^?]*)?(\?(?!.*(key=|token=|secret=|password=|auth=|api_key=|apikey=|access_token=))[^@]*)?$",
    ]

    def __init__(self) -> None:
        self._compiled_test_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.TEST_FILE_PATTERNS
        ]
        self._compiled_value_patterns = [re.compile(p) for p in self.NON_SECRET_VALUE_PATTERNS]

    # Endpoint value types whose resolved path makes a bare `api_path` fragment redundant.
    ENDPOINT_VALUE_TYPES = ("api_endpoint", "full_url", "websocket_url")

    # Line-context hints that mark a finding as documentation/example (downgrade, never drop).
    DOC_CONTEXT_HINTS = {
        "example",
        "sample",
        "demo",
        "readme",
        "docs",
        "documentation",
        "guide",
        "guides",
        "tutorial",
        "snippet",
        "reference",
    }

    @staticmethod
    def _normalize_endpoint_path(value: str) -> str:
        """Extract the path portion of an endpoint value (query/fragment stripped)."""
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            path = urlsplit(value).path or "/"
        else:
            path = value
        return path.split("?", 1)[0].split("#", 1)[0]

    def _endpoint_paths(self, findings: list[Finding], file_url: str = "") -> set[str]:
        """Resolved same-origin/relative endpoint paths used for api_path deduplication.

        An absolute third-party URL with ``/api/x`` must not suppress the application's relative
        ``/api/x``.  Relative values are always eligible; absolute values are eligible only when
        their host matches the analyzed file's host.
        """
        paths: set[str] = set()
        file_host = urlsplit(file_url).netloc.lower() if file_url else ""
        for finding in findings:
            if (
                finding.category == Category.ENDPOINT
                and finding.value_type in self.ENDPOINT_VALUE_TYPES
            ):
                value = finding.extracted_value or ""
                if value.startswith(("http://", "https://", "ws://", "wss://", "//")):
                    parsed = urlsplit("https:" + value if value.startswith("//") else value)
                    base_url = str((finding.metadata or {}).get("base_url") or "").rstrip("/")
                    derived_from_client_base = bool(
                        base_url and value.startswith(base_url + "/")
                    )
                    if (
                        not derived_from_client_base
                        and (not file_host or parsed.netloc.lower() != file_host)
                    ):
                        continue
                paths.add(self._normalize_endpoint_path(finding.extracted_value))
        return paths

    def _is_redundant_api_path(self, finding: Finding, endpoint_paths: set[str]) -> bool:
        """
        True ONLY when this `api_path` fragment EXACTLY equals a resolved endpoint path in the same
        file. Exact match (not prefix): a prefix relationship links DISTINCT endpoints, and the old
        `endpoint.startswith(trimmed + '/')` clause was host-agnostic (endpoint_paths are bare
        paths), so an unrelated THIRD-PARTY URL like `.../api/admin/delete/log` would delete the
        app's own `/api/admin/delete` -- silently dropping a real first-party endpoint. Exact-match
        loses zero detection (the resolved endpoint already carries the identical path).
        """
        raw = finding.extracted_value
        trimmed = raw.split("?", 1)[0].rstrip("/")
        if not trimmed:
            return False
        for endpoint in endpoint_paths:
            if endpoint == trimmed or endpoint == raw:
                return True
        return False

    def _ensure_line_cache(self, source_content: str) -> tuple[list[str], list[int]]:
        """Split source into lines + line-start offsets ONCE per source, and hold per-line result
        caches. All the per-finding context helpers (_check_line_context / _line_has_doc_context /
        _is_line_in_block_comment) reused to split("\n") the whole source AND recompute their line
        result for EVERY finding -> O(findings x line_len), quadratic on a single-line minified
        bundle. Caching by source-object identity collapses that to O(n). Returns (lines, offsets)."""
        if source_content is not getattr(self, "_lc_src", None):
            lines = source_content.split("\n")
            offsets: list[int] = []
            off = 0
            for ln in lines:
                offsets.append(off)
                off += len(ln) + 1
            self._lc_src = source_content
            self._lc_lines = lines
            self._lc_offsets = offsets
            self._lc_signal: dict[int, ContextSignal | None] = {}
            self._lc_doc: dict[int, bool] = {}
        return self._lc_lines, self._lc_offsets

    def _line_has_doc_context(self, source_content: str, line: int) -> bool:
        """True when the finding's own source line reads like docs/example (string contents masked)."""
        if not source_content or line <= 0:
            return False
        lines, _ = self._ensure_line_cache(source_content)
        idx = line - 1
        if idx >= len(lines):
            return False
        cached = self._lc_doc.get(idx)
        if cached is not None:
            return cached
        # Mask string-literal contents so e.g. "api.example.com" inside a string cannot trigger.
        masked = _DOC_MASK_RE.sub('""', lines[idx]).lower()
        result = any(hint in masked for hint in self.DOC_CONTEXT_HINTS)
        self._lc_doc[idx] = result
        return result

    def _apply_doc_downgrade(self, finding: Finding, source_content: str) -> None:
        """Downgrade a DOMAIN/DEBUG finding to LOW + tag when it sits on a documentation line."""
        if self._line_has_doc_context(source_content, finding.evidence.line):
            if finding.confidence != Confidence.LOW:
                finding.confidence = Confidence.LOW
            if "doc-context" not in finding.tags:
                finding.tags.append("doc-context")
            finding.metadata["downgrade_reason"] = "documentation_context"

    def _is_known_provider_secret(self, finding: Finding) -> bool:
        """A finding that matched a NAMED provider pattern (aws_access_key, github_pat,
        stripe_secret_key, private_key, jwt_token, ...) rather than a low-structure heuristic
        (assignment-context GENERIC_PATTERNS or the Shannon-entropy path). Provider matches are
        high-signal credentials that context heuristics must not hard-drop (DQ-C01 / INV-02).

        Generic/heuristic types keep their existing drop-on-FP behavior (they are the noise the
        filter is designed for); only named-provider matches are protected from the hard drop."""
        if "entropy" in (finding.tags or []):
            return False
        # A context override (e.g. _session_context_override) may reclassify a structural provider
        # match (jwt_token/...) to a generic value_type (session_token); the ORIGINAL matched
        # provider pattern is preserved in metadata, so prefer it to avoid hard-dropping a real
        # structural credential on a session/cookie line (INV-02).
        vt = (finding.metadata or {}).get("matched_pattern_type") or finding.value_type or ""
        return vt not in _GENERIC_SECRET_VALUE_TYPES

    def _suppress_but_keep(self, finding: Finding, signals: list[ContextSignal]) -> None:
        """Demote (never drop) a context-suppressed known-provider secret: LOW confidence + a tag +
        an auditable reason, preserving the occurrence for triage (DQ-C01)."""
        finding.confidence = Confidence.LOW
        if "context-suppressed" not in finding.tags:
            finding.tags.append("context-suppressed")
        reasons = [s.reason for s in signals if s.is_false_positive and s.reason]
        finding.metadata["suppression_reason"] = "; ".join(reasons) or "context false-positive"

    def filter_findings(
        self,
        findings: list[Finding],
        ir: IntermediateRepresentation | None = None,
        source_content: str = "",
        file_url: str = "",
    ) -> list[Finding]:
        """
        Filter findings to reduce false positives.

        Args:
            findings: List of findings to filter
            ir: Optional IR for context analysis
            source_content: Source code content
            file_url: File URL for test file detection

        Returns:
            Filtered list of findings
        """
        filtered = []
        seen_values: dict[tuple[str, str, str, int, int], Finding] = {}

        # Check if this is a test/mock file
        is_test_file = self._is_test_file(file_url)

        # FP-reduction pre-pass: resolved endpoint paths, used to drop redundant api_path fragments.
        endpoint_paths = self._endpoint_paths(findings, file_url=file_url)

        for finding in findings:
            category = finding.category

            # ENDPOINT: drop only api_path fragments already covered by a resolved endpoint.
            if category == Category.ENDPOINT:
                if finding.value_type == "api_path" and self._is_redundant_api_path(
                    finding, endpoint_paths
                ):
                    continue  # redundant (the endpoint keeps the path) -> zero detection loss
                filtered.append(finding)
                continue

            # DOMAIN / DEBUG: downgrade (never drop) findings on documentation/example lines.
            if category in (Category.DOMAIN, Category.DEBUG):
                self._apply_doc_downgrade(finding, source_content)
                filtered.append(finding)
                continue

            # FLAG / other non-secret categories: unchanged.
            if category != Category.SECRET:
                filtered.append(finding)
                continue

            signals = self._analyze_context(finding, ir, source_content, is_test_file)

            # Check for strong FP signals
            is_fp = any(s.is_false_positive for s in signals)
            if is_fp:
                if self._is_known_provider_secret(finding):
                    # DQ-C01: a KNOWN-provider credential (matched a NAMED provider pattern, not the
                    # generic Shannon-entropy path) must NEVER be hard-dropped on variable-name /
                    # comment / example-line context -- that silently deletes a real, exposed
                    # credential (doc 07 line 246). Demote to LOW + tag + auditable reason and KEEP it
                    # (occurrence + context preserved) instead of dropping. Only unvalidated
                    # generic-entropy candidates remain eligible for the hard drop.
                    self._suppress_but_keep(finding, signals)
                else:
                    continue

            # Deduplicate only competing classifications of the SAME occurrence.  Value-only
            # deduplication erased repeated exposures on later lines and let the first occurrence's
            # context decide the entire file.
            value_key = (
                finding.extracted_value,
                finding.rule_id,
                finding.evidence.file_url,
                finding.evidence.line,
                finding.evidence.column,
            )
            if value_key in seen_values:
                existing = seen_values[value_key]
                # Keep the more severe finding (higher order = more severe)
                finding_order = _SEVERITY_ORDER.get(finding.severity, 0)
                existing_order = _SEVERITY_ORDER.get(existing.severity, 0)
                # If same severity, prefer higher confidence
                if finding_order > existing_order or (
                    finding_order == existing_order
                    and _CONFIDENCE_ORDER.get(finding.confidence, 0)
                    > _CONFIDENCE_ORDER.get(existing.confidence, 0)
                ):
                    filtered.remove(existing)
                    self._apply_confidence_adjustment(finding, signals)
                    seen_values[value_key] = finding
                    filtered.append(finding)
                continue

            # Adjust confidence based on signals
            self._apply_confidence_adjustment(finding, signals)

            seen_values[value_key] = finding
            filtered.append(finding)

        return filtered

    def _analyze_context(
        self,
        finding: Finding,
        ir: IntermediateRepresentation | None,
        source_content: str,
        is_test_file: bool,
    ) -> list[ContextSignal]:
        """Analyze context around a finding."""
        signals = []

        # Test file -> lower confidence
        if is_test_file:
            signals.append(
                ContextSignal(
                    name="test_file",
                    is_false_positive=False,
                    confidence_adjustment=-0.5,
                    reason="Finding is in a test/mock file",
                )
            )

        # Check variable name context
        var_signal = self._check_variable_context(finding, ir, source_content)
        if var_signal:
            signals.append(var_signal)

        # Check value pattern (non-secret structures)
        value_signal = self._check_value_pattern(finding.extracted_value)
        if value_signal:
            signals.append(value_signal)

        # Check surrounding line context
        line_signal = self._check_line_context(finding, source_content)
        if line_signal:
            signals.append(line_signal)

        return signals

    def _check_variable_context(
        self,
        finding: Finding,
        ir: IntermediateRepresentation | None,
        source_content: str,
    ) -> ContextSignal | None:
        """Check if the value is assigned to a non-secret variable."""
        if not source_content or not finding.evidence.snippet:
            return None

        snippet = finding.evidence.snippet
        value_lower = finding.extracted_value.lower()

        # Look for assignment patterns: varName = "value" (anchor at closing quote)
        assign_pattern = re.compile(
            r'(?:const|let|var)\s+(\w+)\s*=\s*["\']' + re.escape(value_lower) + r'["\']',
            re.IGNORECASE,
        )
        match = assign_pattern.search(snippet)
        if match:
            var_name = match.group(1)
            # Check against non-secret variable names
            var_parts = {
                p.lower() for p in re.split(r"[_\-]|(?<=[a-z])(?=[A-Z])", var_name) if p
            }
            for ns_name in self.NON_SECRET_VAR_NAMES:
                if ns_name in var_parts:
                    return ContextSignal(
                        name="non_secret_variable",
                        is_false_positive=True,
                        confidence_adjustment=-1.0,
                        reason=f"Assigned to non-secret variable: {var_name}",
                    )

        # Check object key context: { someKey: "value" } (anchor at closing quote)
        key_pattern = re.compile(
            r'(?:^|[{,])\s*["\']?(\w+)["\']?\s*:\s*["\']' + re.escape(value_lower) + r'["\']',
            re.IGNORECASE | re.MULTILINE,
        )
        match = key_pattern.search(snippet)
        if match:
            key_name = match.group(1)
            key_parts = {
                p.lower() for p in re.split(r"[_\-]|(?<=[a-z])(?=[A-Z])", key_name) if p
            }
            for ns_name in self.NON_SECRET_VAR_NAMES:
                if ns_name in key_parts:
                    return ContextSignal(
                        name="non_secret_key",
                        is_false_positive=True,
                        confidence_adjustment=-1.0,
                        reason=f"Object key is non-secret type: {key_name}",
                    )

        return None

    def _check_value_pattern(
        self,
        value: str,
    ) -> ContextSignal | None:
        """Check if the value matches non-secret patterns."""
        for pattern in self._compiled_value_patterns:
            if pattern.match(value):
                # A URL normally isn't a secret, but a URL can CARRY one in its path (a webhook
                # token like /hooks/deploy/<TOKEN>) or userinfo -- treating that as a definite
                # non-secret would silently DROP a real hardcoded credential.
                if self._url_carries_credential(value):
                    continue
                return ContextSignal(
                    name="non_secret_pattern",
                    is_false_positive=True,
                    confidence_adjustment=-1.0,
                    reason=f"Value matches non-secret pattern: {pattern.pattern}",
                )
        return None

    @staticmethod
    def _url_carries_credential(value: str) -> bool:
        """True when a URL likely embeds a secret -- userinfo (user:pass@host) or a long,
        digit-bearing path segment (a webhook/token slug, not a plain word slug) -- so it must not
        be filtered away as a benign URL. Non-URL values return False (emails/hex/etc still drop)."""
        if not value.startswith(("http://", "https://", "//")):
            return False
        after_scheme = value.split("//", 1)[-1]
        authority = after_scheme.split("/", 1)[0]
        if "@" in authority:  # user:pass@host userinfo
            return True
        path = after_scheme.split("/", 1)[1] if "/" in after_scheme else ""
        for seg in path.split("?", 1)[0].split("#", 1)[0].split("/"):
            if len(seg) >= 16 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
                return True
        return False

    def _check_line_context(
        self,
        finding: Finding,
        source_content: str,
    ) -> ContextSignal | None:
        """Check surrounding code for context clues."""
        if not source_content:
            return None

        lines, _ = self._ensure_line_cache(source_content)
        line_idx = finding.evidence.line - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None

        # Memoize per line: this ran per SECRET finding and, on a single-line minified bundle,
        # re.search'd the whole source each time -> O(findings x line_len). The result is a pure
        # function of the source line (+ its block-comment membership).
        cached = self._lc_signal.get(line_idx, _UNSET)
        if cached is not _UNSET:
            return cached if isinstance(cached, ContextSignal) else None
        sig = self._compute_line_signal(source_content, lines[line_idx], line_idx)
        self._lc_signal[line_idx] = sig
        return sig

    def _compute_line_signal(
        self,
        source_content: str,
        raw_line: str,
        line_idx: int,
    ) -> ContextSignal | None:
        line = raw_line.strip()

        # Check if line is a comment
        if line.startswith("//") or line.startswith("*") or line.startswith("/*"):
            return ContextSignal(
                name="comment",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in a comment",
            )
        if self._is_line_in_block_comment(source_content, line_idx):
            return ContextSignal(
                name="block_comment",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in a block comment",
            )

        if _EXAMPLE_LINE_RE.search(line):
            return ContextSignal(
                name="example_line",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in example/sample documentation context",
            )

        # Check for console.log/debug context (logged secrets = still a finding,
        # but if it's the FORMAT string, not the secret itself)
        if _CONSOLE_CALL_RE.match(line):
            # Check if the value IS the log message (not a leaked secret)
            if "example" in line.lower() or "test" in line.lower():
                return ContextSignal(
                    name="debug_example",
                    is_false_positive=True,
                    confidence_adjustment=-1.0,
                    reason="Value is in example/test logging",
                )

        return None

    def _is_line_in_block_comment(self, source_content: str, line_idx: int) -> bool:
        """Return True when the 0-based line index falls inside a block comment."""
        if line_idx < 0:
            return False

        lines, line_start_offsets = self._ensure_line_cache(source_content)
        if line_idx >= len(lines):
            return False

        target_start = line_start_offsets[line_idx]
        target_end = target_start + len(lines[line_idx])

        # Pair /* ... */ with str.find (linear) instead of re.finditer(r"/\*[\s\S]*?\*/", ...):
        # the regex is O(n^2) on a source with many unterminated `/*` (e.g. "/*a" repeated), because
        # finditer re-scans to EOF from every `/*` start. Same match set (each `/*` binds to the next
        # `*/`), reached per-finding on attacker-controlled source_content -- a ReDoS otherwise.
        pos = 0
        while True:
            start = source_content.find("/*", pos)
            if start == -1:
                return False
            end = source_content.find("*/", start + 2)
            if end == -1:
                return False
            end += 2  # include the closing */
            if start <= target_start and end >= target_end:
                return True
            pos = end

    def _apply_confidence_adjustment(
        self,
        finding: Finding,
        signals: list[ContextSignal],
    ) -> None:
        """Adjust finding confidence based on signals."""
        # A context-suppressed known-provider secret (DQ-C01) stays LOW -- never re-upgraded by a
        # net-positive signal sum.
        if "context-suppressed" in (finding.tags or []):
            finding.confidence = Confidence.LOW
            return
        total_adjustment = sum(s.confidence_adjustment for s in signals)

        if total_adjustment < -0.3:
            finding.confidence = Confidence.LOW
        elif total_adjustment > 0.3:
            finding.confidence = Confidence.HIGH

    def _is_test_file(self, file_url: str) -> bool:
        """Check if file is a test/mock file."""
        for pattern in self._compiled_test_patterns:
            if pattern.search(file_url):
                return True
        return False
