"""
Source map resolver.

Fetches and parses source maps to recover original source.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin

import httpx


@dataclass
class SourceMapInfo:
    """Information about a source map."""
    url: Optional[str]
    content: Optional[str]
    is_inline: bool
    sources: list[str]
    sources_content: list[Optional[str]]
    mappings: str


@dataclass
class OriginalPosition:
    """Original source position."""
    source: str
    line: int
    column: int
    name: Optional[str]


class SourceMapResolver:
    """
    Resolve and parse JavaScript source maps.
    """

    # Pattern for sourceMappingURL
    SOURCEMAP_URL_PATTERN = re.compile(
        r'(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*(\S+?)(?:\s*\*/)?$',
        re.IGNORECASE | re.MULTILINE
    )

    # Pattern for inline source map (data URL)
    INLINE_SOURCEMAP_PATTERN = re.compile(
        r'data:application/json;(?:charset=[^;]+;)?base64,(.+)$',
        re.IGNORECASE
    )

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Initialize HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
        )

    async def teardown(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "SourceMapResolver":
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.teardown()

    def find_sourcemap_url(self, js_content: str) -> Optional[str]:
        """
        Find sourceMappingURL in JS content.

        Args:
            js_content: JavaScript source code

        Returns:
            Source map URL or None
        """
        match = self.SOURCEMAP_URL_PATTERN.search(js_content)
        if match:
            return match.group(1)
        return None

    async def resolve(
        self,
        js_content: str,
        js_url: str,
    ) -> Optional[SourceMapInfo]:
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
            return None

        # Check for inline source map
        inline_match = self.INLINE_SOURCEMAP_PATTERN.match(sourcemap_ref)
        if inline_match:
            return self._parse_inline_sourcemap(inline_match.group(1))

        # External source map
        sourcemap_url = urljoin(js_url, sourcemap_ref)
        return await self._fetch_sourcemap(sourcemap_url)

    def _parse_inline_sourcemap(self, base64_content: str) -> Optional[SourceMapInfo]:
        """Parse inline (base64-encoded) source map."""
        try:
            decoded = base64.b64decode(base64_content).decode("utf-8")
            return self._parse_sourcemap_json(decoded, is_inline=True)
        except Exception:
            return None

    async def _fetch_sourcemap(self, url: str) -> Optional[SourceMapInfo]:
        """Fetch and parse external source map."""
        if not self._client:
            await self.setup()
        if not self._client:
            return None

        try:
            response = await self._client.get(url)
            if response.status_code != 200:
                return None

            content = response.text
            return self._parse_sourcemap_json(content, is_inline=False, url=url)

        except httpx.HTTPError:
            return None

    def _parse_sourcemap_json(
        self,
        content: str,
        is_inline: bool,
        url: Optional[str] = None,
    ) -> Optional[SourceMapInfo]:
        """Parse source map JSON."""
        try:
            data = json.loads(content)

            return SourceMapInfo(
                url=url,
                content=content,
                is_inline=is_inline,
                sources=data.get("sources", []),
                sources_content=data.get("sourcesContent", []),
                mappings=data.get("mappings", ""),
            )

        except json.JSONDecodeError:
            return None

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
        sources = {}

        for i, source_name in enumerate(sourcemap.sources):
            if i < len(sourcemap.sources_content):
                content = sourcemap.sources_content[i]
                if content:
                    sources[source_name] = content

        return sources

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

        for char in segment:
            digit = self._vlq_char_to_int(char)
            if digit == -1:
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

        return values

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
    ) -> Optional[OriginalPosition]:
        """
        Get original source position for generated position.

        Args:
            sourcemap: Parsed source map
            generated_line: Line in generated file (1-indexed)
            generated_column: Column in generated file (0-indexed)

        Returns:
            OriginalPosition or None
        """
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

        if best_segment and best_segment[0] < len(sourcemap.sources):
            return OriginalPosition(
                source=sourcemap.sources[best_segment[0]],
                line=best_segment[1] + 1,  # Convert to 1-indexed
                column=best_segment[2],
                name=None,
            )

        return None
