"""Tests for fallback YAML loader edge cases."""

from bundleInspector.utils.yaml_loader import _FallbackYamlParser


def test_fallback_yaml_loader_keeps_url_list_items_as_strings():
    """URLs should not be reinterpreted as mapping entries in fallback mode."""
    data = _FallbackYamlParser(
        """
items:
  - https://example.com
"""
    ).parse()

    assert data == {"items": ["https://example.com"]}


def test_fallback_yaml_loader_parses_leading_dot_float():
    """Fallback float parsing should accept `.5`-style values."""
    data = _FallbackYamlParser("threshold: .5\n").parse()

    assert data == {"threshold": 0.5}
