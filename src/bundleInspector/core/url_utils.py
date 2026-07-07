"""Crash-safe URL parsing.

`urllib.parse.urlparse` / `urlsplit` raise ValueError on a malformed authority (e.g. an
unbalanced IPv6 bracket like `https://[${host}]/api`, common in extracted JS endpoint
values and template literals). Untrusted values (finding extracted_value, discovered links)
reach these parsers all over the codebase, and an unguarded ValueError there aborts the whole
scan or report. These drop-in wrappers return an empty-ish result instead of raising; for a
valid URL they are byte-identical to the stdlib functions.
"""

from __future__ import annotations

from urllib.parse import ParseResult, SplitResult, urlparse, urlsplit


def safe_urlparse(url: str, scheme: str = "", allow_fragments: bool = True) -> ParseResult:
    try:
        return urlparse(url, scheme, allow_fragments)
    except (ValueError, AttributeError):
        return ParseResult(scheme="", netloc="", path=url if isinstance(url, str) else "",
                           params="", query="", fragment="")


def safe_urlsplit(url: str, scheme: str = "", allow_fragments: bool = True) -> SplitResult:
    try:
        return urlsplit(url, scheme, allow_fragments)
    except (ValueError, AttributeError):
        return SplitResult(scheme="", netloc="", path=url if isinstance(url, str) else "",
                           query="", fragment="")
