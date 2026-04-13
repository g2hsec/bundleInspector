"""Tests for beautify light deobfuscation safety."""

from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel


def test_light_deobfuscate_preserves_structural_hex_escapes():
    """Quote-like hex escapes should stay escaped to avoid invalid JS output."""
    beautifier = Beautifier(level=NormalizationLevel.LIGHT)

    result = beautifier.beautify(r'var s = "\x22hello\x22";')

    assert result.success is True
    assert '""hello""' not in result.content
    assert r'"\x22hello\x22"' in result.content


def test_light_deobfuscate_decodes_only_active_hex_escapes():
    """Escaped backslashes should preserve literal `\\xNN` sequences."""
    beautifier = Beautifier(level=NormalizationLevel.LIGHT)

    active = beautifier.beautify(r'var active = "\x41";')
    escaped = beautifier.beautify(r'var escaped = "\\x41";')
    mixed = beautifier.beautify(r'var mixed = "\\\x41";')

    assert 'var active = "A";' in active.content
    assert r'var escaped = "\\x41";' in escaped.content
    assert r'var mixed = "\\A";' in mixed.content
