"""
Small YAML loader fallback for dependency-free environments.

This parser intentionally supports the practical subset used by BundleInspector's
config files and shipped rule examples: mappings, lists, quoted scalars,
inline mappings/lists, booleans, nulls, and numeric scalars.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class _Line:
    indent: int
    text: str


def load_yaml(content: str) -> Any:
    """Load YAML using PyYAML when available, else a small fallback parser."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return _FallbackYamlParser(content).parse()
    return yaml.safe_load(content) or {}


class _FallbackYamlParser:
    """Very small indentation-based YAML parser."""

    def __init__(self, content: str):
        self.lines = self._prepare_lines(content)
        self.index = 0

    def parse(self) -> Any:
        """Parse the prepared YAML lines into Python data."""
        if not self.lines:
            return {}
        return self._parse_block(self.lines[0].indent)

    def _prepare_lines(self, content: str) -> list[_Line]:
        prepared: list[_Line] = []
        for raw_line in content.splitlines():
            if not raw_line.strip():
                continue
            stripped = raw_line.lstrip(" ")
            if stripped.startswith("#"):
                continue
            indent = len(raw_line) - len(stripped)
            prepared.append(_Line(indent=indent, text=stripped))
        return prepared

    def _parse_block(self, indent: int) -> Any:
        if self.index >= len(self.lines):
            return {}
        if self.lines[self.index].text.startswith("- "):
            return self._parse_list(indent)
        return self._parse_dict(indent)

    def _parse_dict(self, indent: int) -> dict[str, Any]:
        data: dict[str, Any] = {}
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if line.indent < indent or line.text.startswith("- "):
                break
            if line.indent > indent:
                break

            key, value_text = _split_key_value(line.text)
            self.index += 1
            if value_text == "":
                if self._has_nested(indent):
                    data[key] = self._parse_block(self.lines[self.index].indent)
                else:
                    data[key] = {}
                continue

            value = _parse_scalar(value_text)
            if isinstance(value, dict) and self._has_nested(indent):
                nested = self._parse_block(self.lines[self.index].indent)
                if isinstance(nested, dict):
                    value.update(nested)
            data[key] = value
        return data

    def _parse_list(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if line.indent < indent or not line.text.startswith("- "):
                break
            if line.indent != indent:
                break

            item_text = line.text[2:].strip()
            self.index += 1

            if not item_text:
                item = self._parse_block(self.lines[self.index].indent) if self._has_nested(indent) else None
                items.append(item)
                continue

            mapping_item = _try_parse_mapping_item(item_text)
            if mapping_item is not None:
                key, value_text = mapping_item
                item: Any = {}
                child_indent = line.indent + 2
                if value_text == "":
                    item[key] = self._parse_block(self.lines[self.index].indent) if self._has_nested(line.indent) else {}
                else:
                    item[key] = _parse_scalar(value_text)
                    if self._has_nested(line.indent):
                        nested = self._parse_block(self.lines[self.index].indent)
                        if isinstance(nested, dict):
                            item.update(nested)
                while self.index < len(self.lines):
                    next_line = self.lines[self.index]
                    if next_line.indent < child_indent:
                        break
                    if next_line.indent == indent and next_line.text.startswith("- "):
                        break
                    if next_line.indent != child_indent:
                        break
                    sibling_key, sibling_value_text = _split_key_value(next_line.text)
                    self.index += 1
                    if sibling_value_text == "":
                        item[sibling_key] = (
                            self._parse_block(self.lines[self.index].indent)
                            if self._has_nested(next_line.indent)
                            else {}
                        )
                    else:
                        item[sibling_key] = _parse_scalar(sibling_value_text)
                        if self._has_nested(next_line.indent):
                            nested = self._parse_block(self.lines[self.index].indent)
                            if isinstance(nested, dict):
                                item.update(nested)
                items.append(item)
                continue

            item = _parse_scalar(item_text)
            if isinstance(item, dict) and self._has_nested(indent):
                nested = self._parse_block(self.lines[self.index].indent)
                if isinstance(nested, dict):
                    item.update(nested)
            items.append(item)

        return items

    def _has_nested(self, indent: int) -> bool:
        return self.index < len(self.lines) and self.lines[self.index].indent > indent


def _parse_scalar(value: str) -> Any:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("{") and text.endswith("}"):
        return _parse_inline_mapping(text)
    if text.startswith("[") and text.endswith("]"):
        return _parse_inline_list(text)
    if text[0] in {"'", '"'} and text[-1] == text[0]:
        return _parse_quoted_string(text)

    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None

    if _looks_like_int(text):
        try:
            return int(text)
        except ValueError:
            pass
    if _looks_like_float(text):
        try:
            return float(text)
        except ValueError:
            pass

    return text


def _parse_inline_mapping(text: str) -> dict[str, Any]:
    body = text[1:-1].strip()
    if not body:
        return {}

    data: dict[str, Any] = {}
    for part in _split_top_level(body, ","):
        key, value_text = _split_key_value(part.strip())
        data[key] = _parse_scalar(value_text)
    return data


def _parse_inline_list(text: str) -> list[Any]:
    body = text[1:-1].strip()
    if not body:
        return []
    return [_parse_scalar(part.strip()) for part in _split_top_level(body, ",")]


def _parse_quoted_string(text: str) -> str:
    """Parse a quoted YAML scalar while preserving unknown backslash escapes."""
    quote = text[0]
    inner = text[1:-1]

    if quote == "'":
        return inner.replace("''", "'")

    result: list[str] = []
    index = 0
    escape_map = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        '"': '"',
        "\\": "\\",
    }

    while index < len(inner):
        char = inner[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue

        if index + 1 >= len(inner):
            result.append("\\")
            break

        next_char = inner[index + 1]
        if next_char in escape_map:
            result.append(escape_map[next_char])
        else:
            result.append("\\")
            result.append(next_char)
        index += 2

    return "".join(result)


def _split_key_value(text: str) -> tuple[str, str]:
    separator_index = _find_key_value_separator(text)
    if separator_index is None:
        raise ValueError(f"Invalid YAML mapping entry: {text}")
    return text[:separator_index].strip(), text[separator_index + 1:].strip()


def _try_parse_mapping_item(text: str) -> tuple[str, str] | None:
    try:
        return _split_key_value(text)
    except ValueError:
        return None


def _split_top_level(text: str, delimiter: str, maxsplit: int = -1) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    splits = 0

    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue

        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue

        if char in "{[":
            depth += 1
        elif char in "}]":
            depth = max(depth - 1, 0)

        if char == delimiter and depth == 0 and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(current))
            current = []
            splits += 1
            continue

        current.append(char)

    parts.append("".join(current))
    return parts


def _find_key_value_separator(text: str) -> int | None:
    """Find the first top-level YAML mapping delimiter."""
    depth = 0
    quote = ""

    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue

        if char in {"'", '"'}:
            quote = char
            continue

        if char in "{[":
            depth += 1
            continue
        if char in "}]":
            depth = max(depth - 1, 0)
            continue

        if char != ":" or depth != 0:
            continue

        next_char = text[index + 1] if index + 1 < len(text) else ""
        if not next_char or next_char.isspace():
            return index

    return None


def _looks_like_int(text: str) -> bool:
    return text.isdigit() or (text.startswith("-") and text[1:].isdigit())


def _looks_like_float(text: str) -> bool:
    if text.count(".") != 1:
        return False
    whole, fraction = text.split(".", 1)
    if not fraction:
        return False
    if whole.startswith("-"):
        whole = whole[1:]
    return (whole == "" or whole.isdigit()) and fraction.isdigit()

