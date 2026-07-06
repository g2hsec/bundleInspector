"""Byte -> text decoding for JS assets.

Deliberately dependency-free so the parallel-worker import graph (asset_analyzer)
stays playwright/httpx-free.
"""

from __future__ import annotations


def decode_js_bytes(content: bytes) -> str:
    """Decode JS asset bytes to text, honoring a leading BOM.

    Falls back to UTF-8 with replacement so parsing always proceeds, but a
    UTF-16 or UTF-8-BOM bundle is decoded correctly instead of being mangled
    into U+FFFD replacement chars -- which would silently hide any secrets /
    endpoints embedded in the non-ASCII regions. For BOM-less UTF-8 (the common
    case) this is byte-for-byte identical to `content.decode("utf-8", "replace")`,
    so it does not perturb the detection-invariance gate.
    """
    if not isinstance(content, (bytes, bytearray)):
        return str(content)
    if content.startswith(b"\xef\xbb\xbf"):
        return content.decode("utf-8-sig", errors="replace")
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        # The "utf-16" codec reads and strips the BOM to pick endianness.
        return content.decode("utf-16", errors="replace")
    return content.decode("utf-8", errors="replace")
