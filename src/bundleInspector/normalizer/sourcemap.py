"""
Source map resolver.

Fetches and parses source maps to recover original source.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import posixpath
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Literal
from urllib.parse import unquote_to_bytes, urljoin, urlsplit, urlunsplit

from bundleInspector.core.rate_limiter import AdaptiveRateLimiter, RateLimiter

# NOTE: httpx is imported lazily inside the two async methods that need it (setup /
# _fetch_sourcemap). This keeps `import bundleInspector.normalizer.sourcemap` httpx-free so
# the light per-asset analysis module (which imports SourceMapResolver for offline position
# mapping only) does not drag httpx into spawned worker processes.


@dataclass
class SourceMapSection:
    """One zero-based generated offset and its nested source map."""

    offset_line: int
    offset_column: int
    sourcemap: SourceMapInfo


@dataclass
class SourceMapInfo:
    """Information about a source map."""
    url: str | None
    content: str | None
    is_inline: bool
    sources: list[str]
    sources_content: list[str | None]
    mappings: str
    source_root: str | None = None
    sections: list[SourceMapSection] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    supplemental_sources: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "content": self.content,
            "is_inline": self.is_inline,
            "sources": list(self.sources),
            "sources_content": list(self.sources_content),
            "mappings": self.mappings,
            "source_root": self.source_root,
            "diagnostics": list(self.diagnostics),
            "supplemental_sources": dict(self.supplemental_sources),
            "sections": [
                {
                    "offset_line": section.offset_line,
                    "offset_column": section.offset_column,
                    "sourcemap": section.sourcemap.to_dict(),
                }
                for section in self.sections
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, _depth: int = 0) -> SourceMapInfo:
        if _depth > 4:
            raise ValueError("source map section depth exceeds checkpoint limit")
        sections = []
        raw_sections = data.get("sections")
        if isinstance(raw_sections, list):
            if len(raw_sections) > 10_000:
                raise ValueError("source map section count exceeds checkpoint limit")
            for raw_section in raw_sections:
                if not isinstance(raw_section, dict):
                    continue
                nested = raw_section.get("sourcemap")
                line = raw_section.get("offset_line")
                column = raw_section.get("offset_column")
                if (
                    isinstance(nested, dict)
                    and isinstance(line, int)
                    and isinstance(column, int)
                    and line >= 0
                    and column >= 0
                ):
                    sections.append(
                        SourceMapSection(
                            line,
                            column,
                            cls.from_dict(nested, _depth=_depth + 1),
                        )
                    )
        raw_sources = data.get("sources")
        raw_sources_content = data.get("sources_content")
        raw_mappings = data.get("mappings")
        raw_source_root = data.get("source_root")
        return cls(
            url=data.get("url") if isinstance(data.get("url"), str) else None,
            content=data.get("content") if isinstance(data.get("content"), str) else None,
            is_inline=bool(data.get("is_inline")),
            sources=[item for item in raw_sources if isinstance(item, str)]
            if isinstance(raw_sources, list)
            else [],
            sources_content=[
                item if isinstance(item, str) else None for item in raw_sources_content
            ]
            if isinstance(raw_sources_content, list)
            else [],
            mappings=raw_mappings if isinstance(raw_mappings, str) else "",
            source_root=raw_source_root if isinstance(raw_source_root, str) else None,
            sections=sections,
            diagnostics=[
                item for item in data.get("diagnostics", []) if isinstance(item, str)
            ] if isinstance(data.get("diagnostics"), list) else [],
            supplemental_sources={
                str(key): str(value)
                for key, value in data.get("supplemental_sources", {}).items()
                if isinstance(key, str) and isinstance(value, str)
            } if isinstance(data.get("supplemental_sources"), dict) else {},
        )


@dataclass(frozen=True)
class SourceMapDiagnostic:
    """Bounded, secret-free outcome of the most recent resolution attempt."""

    status: Literal["not_found", "resolved", "failed"]
    discovered: bool
    reason: str | None = None
    reference: str | None = None
    http_status: int | None = None


@dataclass
class OriginalPosition:
    """Original source position."""
    source: str
    line: int
    column: int
    name: str | None


class SourceMapResolver:
    """
    Resolve and parse JavaScript source maps.
    """

    SOURCEMAP_PRAGMA_PATTERN = re.compile(
        r"^\s*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$",
        re.IGNORECASE,
    )

    # Inline maps may be base64 or RFC 2397 percent-encoded JSON.
    DATA_SOURCEMAP_PATTERN = re.compile(
        r"data:application/json(?:;charset=[^;,]+)?(?P<base64>;base64)?,(?P<payload>.*)$",
        re.IGNORECASE,
    )

    MAX_REDIRECTS = 5
    MAX_SOURCEMAP_BYTES = 10 * 1024 * 1024
    MAX_SECTIONS = 10_000
    MAX_SECTION_DEPTH = 4
    MAX_VLQ_VALUE_CHARS = 12

    def __init__(
        self,
        timeout: float = 30.0,
        allow_private_ips: bool = False,
        rate_limiter: RateLimiter | None = None,
        headers_for_url: Callable[[str], Mapping[str, str]] | None = None,
        is_allowed: Callable[[str], bool] | None = None,
        max_retries: int = 0,
        retry_delay: float = 0.0,
    ):
        self.timeout = timeout
        self.allow_private_ips = allow_private_ips
        self.rate_limiter = rate_limiter
        self.headers_for_url = headers_for_url
        self.is_allowed = is_allowed
        self.max_retries = max(0, int(max_retries))
        self.retry_delay = max(0.0, float(retry_delay))
        self._client: Any | None = None
        self.last_diagnostic = SourceMapDiagnostic(
            status="not_found",
            discovered=False,
        )

    @staticmethod
    def _diagnostic_reference(reference: str, *, inline: bool = False) -> str:
        if inline:
            return "[inline-source-map]"
        digest = hashlib.sha256(reference.encode("utf-8", "replace")).hexdigest()[:16]
        try:
            parsed = urlsplit(reference)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                host = parsed.hostname.lower()
                port = f":{parsed.port}" if parsed.port else ""
                return f"{parsed.scheme.lower()}://{host}{port}/[path-{digest}]"
        except ValueError:
            pass
        return f"[source-map-reference-{digest}]"

    def _record_failure(
        self,
        reason: str,
        reference: str,
        *,
        inline: bool = False,
        http_status: int | None = None,
    ) -> None:
        self.last_diagnostic = SourceMapDiagnostic(
            status="failed",
            discovered=True,
            reason=reason,
            reference=self._diagnostic_reference(reference, inline=inline),
            http_status=http_status,
        )

    async def setup(self) -> None:
        """Initialize HTTP client."""
        import httpx

        from bundleInspector.core.safe_http import build_pinned_transport

        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            transport=build_pinned_transport(
                allow_private_ips=self.allow_private_ips,
                max_connections=1,
            ),
            # Redirect targets are attacker-controlled and must be validated one hop at a time.
            follow_redirects=False,
            trust_env=False,
        )

    async def teardown(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> SourceMapResolver:
        await self.setup()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.teardown()

    def find_sourcemap_url(self, js_content: str) -> str | None:
        """
        Find sourceMappingURL in JS content.

        Args:
            js_content: JavaScript source code

        Returns:
            Source map URL or None
        """
        # Only comment tokens can carry a pragma. A regex/string/template containing comment-like
        # text is data and must never trigger network egress. Template interpolation is executable
        # code, so comments inside `${...}` remain visible to this iterative lexical scan.
        found: str | None = None
        mode = "code"
        template_depth = 0
        expression_depths: list[int] = []
        i = 0
        length = len(js_content)
        while i < length:
            char = js_content[i]
            nxt = js_content[i + 1] if i + 1 < length else ""
            if mode in {"single", "double"}:
                if char == "\\":
                    i += 2
                    continue
                if (mode == "single" and char == "'") or (mode == "double" and char == '"'):
                    mode = "code"
                i += 1
                continue
            if mode == "template":
                if char == "\\":
                    i += 2
                    continue
                if char == "`":
                    template_depth -= 1
                    mode = "code"
                    i += 1
                    continue
                if char == "$" and nxt == "{":
                    expression_depths.append(1)
                    mode = "code"
                    i += 2
                    continue
                i += 1
                continue

            if char == "'":
                mode = "single"
            elif char == '"':
                mode = "double"
            elif char == "`":
                template_depth += 1
                mode = "template"
            elif char == "/" and nxt == "/":
                end = i + 2
                while end < length and js_content[end] not in "\r\n":
                    end += 1
                match = self.SOURCEMAP_PRAGMA_PATTERN.match(js_content[i + 2:end])
                if match:
                    found = match.group(1)
                i = end
                continue
            elif char == "/" and nxt == "*":
                end = js_content.find("*/", i + 2)
                if end < 0:
                    end = length
                    advance = end
                else:
                    advance = end + 2
                match = self.SOURCEMAP_PRAGMA_PATTERN.match(js_content[i + 2:end])
                if match:
                    found = match.group(1)
                i = advance
                continue
            elif expression_depths and char == "{":
                expression_depths[-1] += 1
            elif expression_depths and char == "}":
                expression_depths[-1] -= 1
                if expression_depths[-1] == 0:
                    expression_depths.pop()
                    mode = "template"
            i += 1
        return found

    async def resolve(
        self,
        js_content: str,
        js_url: str,
    ) -> SourceMapInfo | None:
        """
        Resolve source map for JS content.

        Args:
            js_content: JavaScript source code
            js_url: URL of the JavaScript file

        Returns:
            SourceMapInfo or None if not available
        """
        sourcemap_ref = self.find_sourcemap_url(js_content)
        if not sourcemap_ref:
            self.last_diagnostic = SourceMapDiagnostic(
                status="not_found",
                discovered=False,
            )
            return None

        # Check for inline source map
        inline_match = self.DATA_SOURCEMAP_PATTERN.match(sourcemap_ref)
        if inline_match:
            result = self._parse_inline_sourcemap(
                inline_match.group("payload"),
                base64_encoded=bool(inline_match.group("base64")),
            )
            if result is None:
                self._record_failure(
                    "inline_decode_or_parse_error",
                    sourcemap_ref,
                    inline=True,
                )
            else:
                self.last_diagnostic = SourceMapDiagnostic(
                    status="resolved",
                    discovered=True,
                    reference=self._diagnostic_reference(sourcemap_ref, inline=True),
                )
            return result

        # External source map
        try:
            sourcemap_url = urljoin(js_url, sourcemap_ref)
        except (TypeError, ValueError):
            self._record_failure("invalid_sourcemap_url", sourcemap_ref)
            return None
        return await self._fetch_sourcemap(sourcemap_url)

    def parse_content(
        self,
        content: str,
        *,
        url: str | None = None,
        is_inline: bool = False,
    ) -> SourceMapInfo | None:
        """Parse already-available map content without performing network I/O."""
        reference = url or "embedded-source-map"
        result = self._parse_sourcemap_json(content, is_inline=is_inline, url=url)
        if result is None:
            self._record_failure(
                "malformed_sourcemap",
                reference,
                inline=is_inline,
            )
            return None
        self.last_diagnostic = SourceMapDiagnostic(
            status="resolved",
            discovered=True,
            reference=self._diagnostic_reference(reference, inline=is_inline),
        )
        return result

    def _parse_inline_sourcemap(
        self,
        encoded_content: str,
        *,
        base64_encoded: bool,
    ) -> SourceMapInfo | None:
        """Parse a bounded base64 or percent-encoded RFC 2397 source map."""
        encoded_limit = (
            (self.MAX_SOURCEMAP_BYTES * 4 // 3) + 4
            if base64_encoded
            else self.MAX_SOURCEMAP_BYTES * 3
        )
        if len(encoded_content) > encoded_limit:
            return None
        try:
            raw = (
                base64.b64decode(encoded_content, validate=True)
                if base64_encoded
                else unquote_to_bytes(encoded_content)
            )
            if len(raw) > self.MAX_SOURCEMAP_BYTES:
                return None
            decoded = raw.decode("utf-8")
            return self._parse_sourcemap_json(decoded, is_inline=True)
        except (ValueError, UnicodeError):
            return None

    async def _bounded_get(
        self,
        url: str,
        headers: Mapping[str, str],
    ) -> tuple[int, dict[str, str], str | None, bool]:
        """Return status/headers/bounded UTF-8 body without buffering oversized responses."""
        client = self._client
        if client is None:
            raise RuntimeError("source map HTTP client is unavailable")
        stream = getattr(client, "stream", None)
        if callable(stream):
            kwargs = {"headers": dict(headers)} if headers else {}
            async with stream("GET", url, **kwargs) as response:
                status = int(response.status_code)
                response_headers = {
                    str(key).lower(): str(value) for key, value in response.headers.items()
                }
                if status != 200:
                    return status, response_headers, None, False
                content_length = response_headers.get("content-length")
                try:
                    if content_length is not None and int(content_length) > self.MAX_SOURCEMAP_BYTES:
                        return status, response_headers, None, True
                except ValueError:
                    pass
                body = bytearray()
                chunks = response.aiter_bytes()
                try:
                    async for chunk in chunks:
                        if len(body) + len(chunk) > self.MAX_SOURCEMAP_BYTES:
                            return status, response_headers, None, True
                        body.extend(chunk)
                finally:
                    close_chunks = getattr(chunks, "aclose", None)
                    if callable(close_chunks):
                        await close_chunks()
                try:
                    return status, response_headers, bytes(body).decode("utf-8"), False
                except UnicodeDecodeError:
                    return status, response_headers, None, False

        response = (
            await client.get(url, headers=dict(headers))
            if headers
            else await client.get(url)
        )
        status = int(response.status_code)
        response_headers = {
            str(key).lower(): str(value)
            for key, value in (getattr(response, "headers", {}) or {}).items()
        }
        if status != 200:
            return status, response_headers, None, False
        content = str(getattr(response, "text", "") or "")
        too_large = len(content.encode("utf-8", errors="replace")) > self.MAX_SOURCEMAP_BYTES
        return status, response_headers, None if too_large else content, too_large

    async def _fetch_sourcemap(self, url: str) -> SourceMapInfo | None:
        """Fetch and parse external source map."""
        from bundleInspector.core.security import is_url_safe

        diagnostic_url = url
        if not self._client:
            await self.setup()
        if not self._client:
            self._record_failure("client_unavailable", diagnostic_url)
            return None

        current_url = url
        redirect_statuses = {301, 302, 303, 307, 308}
        try:
            for hop in range(self.MAX_REDIRECTS + 1):
                # SSRF guard: validate immediately before every network egress. With automatic
                # redirects disabled, no redirect can bypass this check or carry implicit auth /
                # custom headers to another origin (this resolver deliberately sends none).
                if self.is_allowed is not None and not self.is_allowed(current_url):
                    self._record_failure(
                        "out_of_scope_redirect" if hop else "out_of_scope_url",
                        current_url,
                    )
                    return None
                is_safe, _reason = is_url_safe(
                    current_url,
                    False,
                    self.allow_private_ips,
                )
                if not is_safe:
                    self._record_failure(
                        "unsafe_redirect" if hop else "unsafe_url",
                        current_url,
                    )
                    return None

                attempts = self.max_retries + 1
                for attempt in range(attempts):
                    if self.rate_limiter is not None:
                        await self.rate_limiter.acquire(current_url)
                        await self.rate_limiter.acquire_slot()
                    try:
                        request_headers = (
                            dict(self.headers_for_url(current_url))
                            if self.headers_for_url is not None
                            else {}
                        )
                        status_code, response_headers, content, too_large = await self._bounded_get(
                            current_url,
                            request_headers,
                        )
                        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                            if status_code == 429 or status_code >= 500:
                                await self.rate_limiter.record_error(current_url, status_code)
                            else:
                                await self.rate_limiter.record_success(current_url)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                            await self.rate_limiter.record_error(current_url, 0)
                        if attempt + 1 >= attempts:
                            raise
                        await asyncio.sleep(self.retry_delay)
                        continue
                    finally:
                        if self.rate_limiter is not None:
                            self.rate_limiter.release_slot()
                    if (status_code == 429 or status_code >= 500) and attempt + 1 < attempts:
                        await asyncio.sleep(self.retry_delay)
                        continue
                    break
                if status_code in redirect_statuses:
                    if hop >= self.MAX_REDIRECTS:
                        self._record_failure("redirect_limit", current_url)
                        return None
                    location = response_headers.get("location")
                    if not isinstance(location, str) or not location.strip():
                        self._record_failure("redirect_missing_location", current_url)
                        return None
                    try:
                        current_url = urljoin(current_url, location.strip())
                    except (TypeError, ValueError):
                        self._record_failure("invalid_redirect_url", current_url)
                        return None
                    continue

                if status_code != 200:
                    self._record_failure(
                        "http_status",
                        current_url,
                        http_status=status_code,
                    )
                    return None
                if too_large:
                    self._record_failure("response_too_large", current_url)
                    return None
                if content is None:
                    self._record_failure("malformed_sourcemap", current_url)
                    return None
                result = self._parse_sourcemap_json(
                    content,
                    is_inline=False,
                    url=current_url,
                )
                if result is None:
                    self._record_failure("malformed_sourcemap", current_url)
                    return None
                self.last_diagnostic = SourceMapDiagnostic(
                    status="resolved",
                    discovered=True,
                    reference=self._diagnostic_reference(current_url),
                )
                return result
            return None

        except Exception:
            # ANY failure fetching/decoding an external sourcemap must return None, never
            # abort the scan (a non-200 body, a decode error, a malformed map, etc.).
            self._record_failure("fetch_error", current_url)
            return None

    def _parse_sourcemap_json(
        self,
        content: str,
        is_inline: bool,
        url: str | None = None,
    ) -> SourceMapInfo | None:
        """Parse source map JSON.

        Robust against JSON that is valid but not an object (`null`/`[]`/number/string),
        deeply-nested JSON (RecursionError from json.loads), and `null` sources/sourcesContent
        -- each of which would otherwise raise and abort the entire scan.
        """
        if len(content) > self.MAX_SOURCEMAP_BYTES:
            return None
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None
        return self._parse_sourcemap_object(
            data,
            content=content,
            is_inline=is_inline,
            url=url,
            depth=0,
        )

    def _parse_sourcemap_object(
        self,
        data: dict[str, Any],
        *,
        content: str | None,
        is_inline: bool,
        url: str | None,
        depth: int,
    ) -> SourceMapInfo | None:
        if data.get("version") != 3 or depth > self.MAX_SECTION_DEPTH:
            return None
        source_root = data.get("sourceRoot")
        if source_root is not None and not isinstance(source_root, str):
            return None
        raw_sections = data.get("sections")
        if raw_sections is not None:
            if (
                not isinstance(raw_sections, list)
                or not raw_sections
                or len(raw_sections) > self.MAX_SECTIONS
                or depth >= self.MAX_SECTION_DEPTH
            ):
                return None
            sections: list[SourceMapSection] = []
            previous_offset: tuple[int, int] | None = None
            for raw_section in raw_sections:
                if not isinstance(raw_section, dict):
                    return None
                raw_offset = raw_section.get("offset")
                nested = raw_section.get("map")
                if not isinstance(raw_offset, dict) or not isinstance(nested, dict):
                    return None
                line = raw_offset.get("line")
                column = raw_offset.get("column")
                if (
                    type(line) is not int
                    or type(column) is not int
                    or line < 0
                    or column < 0
                ):
                    return None
                offset = (line, column)
                if previous_offset is not None and offset <= previous_offset:
                    return None
                nested_map = self._parse_sourcemap_object(
                    nested,
                    content=None,
                    is_inline=is_inline,
                    url=url,
                    depth=depth + 1,
                )
                if nested_map is None:
                    return None
                if source_root and not nested_map.source_root:
                    nested_map.source_root = source_root
                sections.append(SourceMapSection(line, column, nested_map))
                previous_offset = offset
            return SourceMapInfo(
                url=url,
                content=content,
                is_inline=is_inline,
                sources=[],
                sources_content=[],
                mappings="",
                source_root=source_root,
                sections=sections,
                diagnostics=sorted({
                    diagnostic
                    for section in sections
                    for diagnostic in section.sourcemap.diagnostics
                }),
            )

        sources = data.get("sources")
        if sources is None:
            normalized_sources: list[str] = []
        elif isinstance(sources, list) and all(isinstance(item, str) for item in sources):
            normalized_sources = list(sources)
        else:
            return None
        sources_content = data.get("sourcesContent")
        if sources_content is None:
            normalized_content: list[str | None] = []
        elif isinstance(sources_content, list) and all(
            item is None or isinstance(item, str) for item in sources_content
        ):
            normalized_content = list(sources_content)
        else:
            return None
        mappings = data.get("mappings", "")
        if not isinstance(mappings, str):
            return None
        result = SourceMapInfo(
            url=url,
            content=content,
            is_inline=is_inline,
            sources=normalized_sources,
            sources_content=normalized_content,
            mappings=mappings,
            source_root=source_root,
        )
        result.diagnostics.extend(self._mapping_diagnostics(mappings))
        return result

    def _mapping_diagnostics(self, mappings: str) -> list[str]:
        value_chars = 0
        for char in mappings:
            if char in ",;":
                if value_chars:
                    return ["vlq_unterminated_value"]
                value_chars = 0
                continue
            digit = self._VLQ_CHAR_MAP.get(char)
            if digit is None:
                return ["vlq_invalid_character"]
            value_chars += 1
            if value_chars > self.MAX_VLQ_VALUE_CHARS:
                return ["vlq_value_too_long"]
            if not digit & 32:
                value_chars = 0
        return ["vlq_unterminated_value"] if value_chars else []

    @staticmethod
    def _escaped_source_name(source_root: str, source: str) -> str:
        root_digest = hashlib.sha256(
            source_root.encode("utf-8", "replace")
        ).hexdigest()[:16]
        source_digest = hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()[:16]
        return f"[source-root:{root_digest}]/[escaped-source:{source_digest}]"

    def _resolve_source_name(self, sourcemap: SourceMapInfo, source: str) -> str:
        source_root = sourcemap.source_root
        if not source_root:
            if not sourcemap.url:
                return source
            try:
                return urljoin(sourcemap.url, source)
            except (TypeError, ValueError):
                return self._escaped_source_name(sourcemap.url, source)

        try:
            resolved_root = (
                urljoin(
                    sourcemap.url,
                    source_root if source_root.endswith("/") else f"{source_root}/",
                )
                if sourcemap.url
                else source_root
            )
        except (TypeError, ValueError):
            return self._escaped_source_name("[invalid-source-root]", source)
        try:
            root_url = urlsplit(resolved_root)
        except ValueError:
            return self._escaped_source_name("[invalid-source-root]", source)
        if root_url.scheme in {"http", "https"} and root_url.hostname:
            try:
                candidate = urljoin(resolved_root, source)
                candidate_url = urlsplit(candidate)
                root_port = root_url.port or (443 if root_url.scheme == "https" else 80)
                candidate_port = candidate_url.port or (
                    443 if candidate_url.scheme == "https" else 80
                )
            except ValueError:
                return self._escaped_source_name(resolved_root, source)
            root_path = posixpath.normpath(root_url.path or "/")
            candidate_path = posixpath.normpath(candidate_url.path or "/")
            contained = candidate_path == root_path or candidate_path.startswith(
                root_path.rstrip("/") + "/"
            )
            same_origin = (
                candidate_url.scheme.lower() == root_url.scheme.lower()
                and (candidate_url.hostname or "").lower() == root_url.hostname.lower()
                and candidate_port == root_port
            )
            if not same_origin or not contained:
                return self._escaped_source_name(resolved_root, source)
            return urlunsplit(
                (
                    candidate_url.scheme.lower(),
                    candidate_url.netloc,
                    candidate_path,
                    "",
                    "",
                )
            )

        normalized_root = posixpath.normpath("/" + resolved_root.replace("\\", "/").lstrip("/"))
        normalized_source = source.replace("\\", "/")
        candidate_path = posixpath.normpath(f"{normalized_root}/{normalized_source}")
        if candidate_path != normalized_root and not candidate_path.startswith(
            normalized_root.rstrip("/") + "/"
        ):
            return self._escaped_source_name(normalized_root, source)
        return candidate_path

    def get_original_sources(
        self,
        sourcemap: SourceMapInfo,
    ) -> dict[str, str]:
        """
        Extract original source files from source map.

        Args:
            sourcemap: Parsed source map info

        Returns:
            Dict mapping source names to content
        """
        pairs: list[tuple[str, str]] = []

        def collect(source_map: SourceMapInfo) -> None:
            pairs.extend(source_map.supplemental_sources.items())
            for section in source_map.sections:
                collect(section.sourcemap)
            for index, source_name in enumerate(source_map.sources):
                if index >= len(source_map.sources_content):
                    continue
                content = source_map.sources_content[index]
                if content:
                    pairs.append((self._resolve_source_name(source_map, source_name), content))

        collect(sourcemap)
        unique_pairs = sorted(set(pairs))
        digest_pairs = [
            (
                path,
                hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()[:16],
            )
            for path, content in unique_pairs
        ]
        identities = self._source_identity_keys(digest_pairs)
        return {
            identity: unique_pairs[index][1]
            for index, identity in enumerate(identities)
        }

    def _resolved_source_identities(self, sourcemap: SourceMapInfo) -> list[str]:
        """Return deterministic path+content identities without last-wins collisions."""
        resolved = [self._resolve_source_name(sourcemap, name) for name in sourcemap.sources]
        pairs: list[tuple[str, str]] = []
        for index, path in enumerate(resolved):
            content = (
                sourcemap.sources_content[index]
                if index < len(sourcemap.sources_content)
                else None
            )
            digest = hashlib.sha256((content or "").encode("utf-8", "surrogatepass")).hexdigest()[:16]
            pairs.append((path, digest))

        return self._source_identity_keys(pairs)

    @staticmethod
    def _source_identity_keys(pairs: list[tuple[str, str]]) -> list[str]:
        grouped: dict[str, set[str]] = {}
        for path, digest in pairs:
            grouped.setdefault(path, set()).add(digest)
        identity_by_pair: dict[tuple[str, str], str] = {}
        assigned: dict[str, tuple[str, str]] = {}
        for pair in sorted(set(pairs)):
            path, digest = pair
            candidate = (
                f"{path}#bundleinspector-source={digest}"
                if len(grouped.get(path, ())) > 1
                else path
            )
            collision_index = 0
            while candidate in assigned and assigned[candidate] != pair:
                token = hashlib.sha256(
                    f"{path}\0{digest}\0{collision_index}".encode("utf-8", "surrogatepass")
                ).hexdigest()[:24]
                candidate = f"[source-identity:{token}]"
                collision_index += 1
            assigned[candidate] = pair
            identity_by_pair[pair] = candidate
        return [identity_by_pair[pair] for pair in pairs]

    def decode_mappings(
        self,
        sourcemap: SourceMapInfo,
    ) -> list[list[tuple[int, ...]]]:
        """
        Decode VLQ mappings from source map.

        Returns list of line mappings, where each line is a list of
        segment tuples (generated_column, source_index, original_line,
        original_column, [name_index]).
        """
        mappings = sourcemap.mappings
        if not mappings:
            return []

        lines = []
        for line in mappings.split(";"):
            segments = []
            if line:
                for segment in line.split(","):
                    if segment:
                        decoded = self._decode_vlq(segment)
                        if decoded:
                            segments.append(tuple(decoded))
            lines.append(segments)

        return lines

    def _decode_vlq(self, segment: str) -> list[int]:
        """Decode VLQ-encoded segment."""
        VLQ_BASE = 32
        VLQ_CONTINUATION = 32

        values = []
        shift = 0
        value = 0
        value_chars = 0

        for char in segment:
            digit = self._vlq_char_to_int(char)
            if digit == -1:
                return []
            value_chars += 1
            if value_chars > self.MAX_VLQ_VALUE_CHARS:
                return []

            continuation = digit & VLQ_CONTINUATION
            digit &= VLQ_BASE - 1
            value += digit << shift

            if continuation:
                shift += 5
            else:
                # Sign is in the least significant bit
                if value & 1:
                    value = -(value >> 1)
                else:
                    value = value >> 1

                values.append(value)
                shift = 0
                value = 0
                value_chars = 0

        return values if value_chars == 0 else []

    _VLQ_CHAR_MAP: dict[str, int] = {
        c: i for i, c in enumerate(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )
    }

    def _vlq_char_to_int(self, char: str) -> int:
        """Convert VLQ character to integer."""
        return self._VLQ_CHAR_MAP.get(char, -1)

    def get_original_position(
        self,
        sourcemap: SourceMapInfo,
        generated_line: int,
        generated_column: int,
    ) -> OriginalPosition | None:
        """
        Get original source position for generated position.

        Args:
            sourcemap: Parsed source map
            generated_line: Line in generated file (1-indexed)
            generated_column: Column in generated file (0-indexed)

        Returns:
            OriginalPosition or None
        """
        if generated_line < 1 or generated_column < 0:
            return None
        if sourcemap.sections:
            target = (generated_line - 1, generated_column)
            selected: SourceMapSection | None = None
            for section in sourcemap.sections:
                if (section.offset_line, section.offset_column) <= target:
                    selected = section
                else:
                    break
            if selected is None:
                return None
            relative_line_zero = generated_line - 1 - selected.offset_line
            relative_column = (
                generated_column - selected.offset_column
                if relative_line_zero == 0
                else generated_column
            )
            if relative_line_zero < 0 or relative_column < 0:
                return None
            return self.get_original_position(
                selected.sourcemap,
                relative_line_zero + 1,
                relative_column,
            )

        lines = self.decode_mappings(sourcemap)

        if generated_line < 1 or generated_line > len(lines):
            return None

        # VLQ values are relative: source_index, original_line,
        # original_column carry across lines; gen_column resets per line.
        # Accumulate from all previous lines first.
        source_index = 0
        original_line = 0
        original_column = 0

        for line_idx in range(generated_line - 1):
            for segment in lines[line_idx]:
                if len(segment) >= 4:
                    source_index += segment[1]
                    original_line += segment[2]
                    original_column += segment[3]

        # Now process the target line
        line_segments = lines[generated_line - 1]
        if not line_segments:
            return None

        gen_column = 0
        best_segment = None

        for segment in line_segments:
            gen_column += segment[0]
            if len(segment) >= 4:
                source_index += segment[1]
                original_line += segment[2]
                original_column += segment[3]

                if gen_column <= generated_column:
                    best_segment = (source_index, original_line, original_column)

        sources = self._resolved_source_identities(sourcemap)
        # Guard non-negative cumulative indices: a malformed relative VLQ map can drive the
        # source index or original line negative, which would wrap to the wrong source /
        # produce a non-positive line, or (sources=None) raise TypeError.
        if best_segment and 0 <= best_segment[0] < len(sources) and best_segment[1] >= 0:
            return OriginalPosition(
                source=sources[best_segment[0]],
                line=best_segment[1] + 1,  # Convert to 1-indexed
                column=max(0, best_segment[2]),
                name=None,
            )

        return None
