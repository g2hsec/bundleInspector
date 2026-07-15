"""Portable validation for identifiers that become filesystem path components."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import TypeGuard

PORTABLE_COMPONENT_MAX_LENGTH = 128
_PORTABLE_COMPONENT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_WINDOWS_DEVICE_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def is_reparse_path(path: Path) -> bool:
    """Return whether an existing path is a symlink or Windows reparse point.

    Missing paths return ``False`` so callers can distinguish absence with their
    own existence policy. Other filesystem errors propagate and fail closed.
    """
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def is_portable_component(value: object) -> TypeGuard[str]:
    """Return whether *value* has one unambiguous spelling on supported filesystems."""
    if not isinstance(value, str) or _PORTABLE_COMPONENT_RE.fullmatch(value) is None:
        return False
    if value.endswith("."):
        return False
    return value.split(".", 1)[0] not in _WINDOWS_DEVICE_NAMES


def validate_portable_component(value: str, *, label: str = "identifier") -> str:
    """Return *value* or raise when it is unsafe as a portable path component."""
    if not is_portable_component(value):
        raise ValueError(
            f"{label} must be a lowercase portable identifier "
            "(no paths, aliases, trailing dots, or Windows device names)"
        )
    return value
