"""Tests for fallback YAML loader edge cases and shipped-document parity."""

from pathlib import Path

import pytest

from bundleInspector.utils.yaml_loader import _FallbackYamlParser, load_yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_YAML = tuple(sorted((REPO_ROOT / "examples").rglob("*.yml"))) + tuple(
    sorted((REPO_ROOT / "examples").rglob("*.yaml"))
)


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


def test_load_yaml_tolerates_regex_backslash_escape_in_double_quotes():
    r"""A custom-rule regex with an invalid-YAML escape (\s) in a DOUBLE-quoted scalar must load the
    same whether or not PyYAML is installed -- PyYAML alone rejects it, so load_yaml retries with the
    tolerant fallback. The regex must survive intact."""
    data = load_yaml(r'pattern: "(?i)^Bearer\s+[A-Za-z0-9\-\._]+"')
    assert data == {"pattern": r"(?i)^Bearer\s+[A-Za-z0-9\-\._]+"}


def test_load_yaml_valid_yaml_still_parsed_by_pyyaml():
    """Valid YAML is unaffected by the tolerance retry (it never raises, so PyYAML handles it)."""
    data = load_yaml("a: 1\nb:\n  - x\n  - y\nc: true\nd: null")
    assert data == {"a": 1, "b": ["x", "y"], "c": True, "d": None}


def test_load_yaml_non_escape_error_still_raises():
    """Only unknown-escape failures are retried; other malformed YAML must still surface an error."""
    import yaml
    with pytest.raises(yaml.YAMLError):
        load_yaml("key: [unclosed")


def test_fallback_yaml_loader_strips_only_real_inline_comments() -> None:
    data = _FallbackYamlParser(
        'count: 10 # integer\nquoted: "value # retained" # removed\nfragment: /path#anchor\n'
    ).parse()

    assert data == {
        "count": 10,
        "quoted": "value # retained",
        "fragment": "/path#anchor",
    }


@pytest.mark.parametrize("path", SHIPPED_YAML, ids=lambda path: path.relative_to(REPO_ROOT).as_posix())
def test_fallback_matches_pyyaml_for_every_shipped_yaml(path: Path) -> None:
    import yaml

    content = path.read_text(encoding="utf-8")
    expected = yaml.safe_load(content) or {}

    assert _FallbackYamlParser(content).parse() == expected
    assert load_yaml(content) == expected
