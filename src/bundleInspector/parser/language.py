"""Language hints inferred from local or virtual JavaScript-family paths."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import unquote, urlsplit

LanguageHint = Literal["javascript", "jsx", "typescript", "tsx"]

_EXTENSION_HINTS: dict[str, LanguageHint] = {
    ".cjs": "javascript",
    ".cts": "typescript",
    ".js": "javascript",
    ".json": "javascript",
    ".jsx": "jsx",
    ".mjs": "javascript",
    ".mts": "typescript",
    ".ts": "typescript",
    ".tsx": "tsx",
}


def language_hint_from_path(value: str) -> LanguageHint | None:
    """Return the grammar implied by a URL/path suffix, ignoring query and fragment text."""
    if not value:
        return None

    # ``urlsplit`` treats ``C:\\path`` as a URL with scheme ``c``. Keep Windows drive paths as
    # plain paths, while normal URLs use their decoded path component.
    if len(value) >= 2 and value[1] == ":":
        path = value.split("#", 1)[0].split("?", 1)[0]
    else:
        path = urlsplit(value).path
    suffix = PurePosixPath(unquote(path).replace("\\", "/")).suffix.lower()
    return _EXTENSION_HINTS.get(suffix)
