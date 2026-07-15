"""Byte -> text decoding for JS assets.

Deliberately dependency-free so the parallel-worker import graph (asset_analyzer)
stays playwright/httpx-free.
"""

from __future__ import annotations

_ENCODING_PROBE_BYTES = 8192
_TEXT_PROBE_CHARS = 4096


def _zero_ratio(values: bytes) -> float:
    """Return the NUL ratio for one sampled byte lane."""
    if not values:
        return 0.0
    return values.count(0) / len(values)


def _looks_like_text(value: str) -> bool:
    """Reject binary-looking decodes before accepting a BOM-less Unicode guess."""
    sample = value[:_TEXT_PROBE_CHARS]
    if not sample:
        return True
    disallowed = sum(
        char == "\x00" or (ord(char) < 0x20 and char not in "\t\r\n\f")
        for char in sample
    )
    return disallowed / len(sample) <= 0.02


def _decode_bomless_unicode(content: bytes) -> str | None:
    """Conservatively recognize common BOM-less UTF-16/32 byte-lane patterns."""
    if len(content) < 4:
        return None

    probe = content[:_ENCODING_PROBE_BYTES]
    lanes4 = [probe[offset::4] for offset in range(4)]
    ratios4 = [_zero_ratio(lane) for lane in lanes4]
    candidates: list[str] = []

    # ASCII-heavy JS in UTF-32 has three near-empty byte lanes. Check this before UTF-16,
    # because the same bytes can also resemble a UTF-16 stream with alternating NUL code units.
    if ratios4[1] >= 0.70 and ratios4[2] >= 0.70 and ratios4[3] >= 0.70 and ratios4[0] <= 0.20:
        candidates.append("utf-32-le")
    if ratios4[0] >= 0.70 and ratios4[1] >= 0.70 and ratios4[2] >= 0.70 and ratios4[3] <= 0.20:
        candidates.append("utf-32-be")

    even_ratio = _zero_ratio(probe[0::2])
    odd_ratio = _zero_ratio(probe[1::2])
    if odd_ratio >= 0.60 and even_ratio <= 0.20:
        candidates.append("utf-16-le")
    if even_ratio >= 0.60 and odd_ratio <= 0.20:
        candidates.append("utf-16-be")

    for encoding in candidates:
        try:
            decoded = content.decode(encoding, errors="strict")
        except (UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(decoded):
            return decoded
    return None


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
    content = bytes(content)
    if content.startswith(b"\xef\xbb\xbf"):
        return content.decode("utf-8-sig", errors="replace")
    if content.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        # Check UTF-32 first: the little-endian BOM starts with the UTF-16LE BOM.
        return content.decode("utf-32", errors="replace")
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        # The "utf-16" codec reads and strips the BOM to pick endianness.
        return content.decode("utf-16", errors="replace")
    decoded = _decode_bomless_unicode(content)
    if decoded is not None:
        return decoded
    return content.decode("utf-8", errors="replace")
