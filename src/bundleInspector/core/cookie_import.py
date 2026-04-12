"""
Browser cookie import utilities.

Supports importing cookies from:
- Netscape/curl cookie files
- JSON cookie array (browser extension export)
- EditThisCookie JSON format
- Chrome/Firefox cookie header string
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def import_cookies(source: str, domain: str = "") -> dict[str, str]:
    """
    Import cookies from various sources.

    Auto-detects the format based on content/path.

    Args:
        source: File path, browser name, or cookie string
        domain: Optional domain filter

    Returns:
        Dict of cookie name → value
    """
    # Check if it's a file path
    path = Path(source)
    if path.exists() and path.is_file():
        return import_cookies_from_file(path, domain)

    # Check if it's a browser name
    if source.lower() in ("chrome", "firefox", "edge", "chromium"):
        return import_cookies_from_browser(source.lower(), domain)

    # Treat as cookie header string: "name1=val1; name2=val2"
    return parse_cookie_header(source)


def import_cookies_from_file(
    path: Path,
    domain: str = "",
) -> dict[str, str]:
    """Import cookies from a file (auto-detect format)."""
    content = path.read_text(encoding="utf-8", errors="replace")
    stripped = content.strip()

    # JSON array format
    if stripped.startswith("["):
        return parse_json_cookies(stripped, domain)

    # JSON object format - could be a single cookie or a wrapper
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            # Check if it's a wrapper with a cookies array inside
            if isinstance(data, dict):
                for key in ("cookies", "cookie", "data"):
                    if key in data and isinstance(data[key], list):
                        return parse_json_cookies(json.dumps(data[key]), domain)
            # Otherwise treat as single cookie object
            return parse_json_cookies(f"[{stripped}]", domain)
        except json.JSONDecodeError:
            return parse_json_cookies(f"[{stripped}]", domain)

    # Netscape cookie file format
    has_netscape_header = "# Netscape HTTP Cookie File" in content
    has_tab_fields = any(
        len(line.split("\t")) == 7
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    if has_netscape_header or has_tab_fields:
        return parse_netscape_cookies(content, domain)

    # Header string format: name=value; name2=value2 (or single cookie without semicolon)
    if "=" in content:
        return parse_cookie_header(content)

    logger.warning(f"Could not detect cookie file format: {path}")
    return {}


def parse_json_cookies(
    content: str,
    domain: str = "",
) -> dict[str, str]:
    """
    Parse cookies from JSON array format.

    Supports:
    - EditThisCookie export: [{"name": "x", "value": "y", "domain": ".example.com"}]
    - Simple format: [{"name": "x", "value": "y"}]
    - Cookie-Editor format: [{"name": "x", "value": "y", "domain": ".example.com"}]
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON cookie data: {e}")
        return {}

    cookies = {}

    for item in data:
        if not isinstance(item, dict):
            continue

        name = item.get("name", "")
        value = item.get("value", "")

        if not name:
            continue

        # Filter by domain if specified
        if domain:
            cookie_domain = item.get("domain", "")
            if cookie_domain and not _domain_matches(cookie_domain, domain):
                continue

        cookies[name] = value

    return cookies


def parse_netscape_cookies(
    content: str,
    domain: str = "",
) -> dict[str, str]:
    """
    Parse Netscape/curl cookie file format.

    Format: domain\\tinclude_subdomains\\tpath\\tsecure\\texpiry\\tname\\tvalue
    Lines starting with # are comments.
    """
    cookies = {}

    for line in content.split("\n"):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            continue

        cookie_domain = parts[0]
        name = parts[5]
        value = parts[6]

        if not name:
            continue

        # Filter by domain
        if domain and not _domain_matches(cookie_domain, domain):
            continue

        cookies[name] = value

    return cookies


def parse_cookie_header(header: str) -> dict[str, str]:
    """
    Parse cookie header string.

    Format: "name1=value1; name2=value2"
    """
    cookies = {}

    # Clean up multiline
    header = header.strip().replace("\n", "").replace("\r", "")

    # Remove "Cookie: " prefix if present
    if header.lower().startswith("cookie:"):
        header = header[7:].strip()

    for pair in header.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue

        name, value = pair.split("=", 1)
        name = name.strip()
        value = value.strip()

        if name:
            cookies[name] = value

    return cookies


def import_cookies_from_browser(
    browser: str,
    domain: str = "",
) -> dict[str, str]:
    """
    Import cookies from a browser's cookie database.

    Reads the SQLite cookie database directly.
    Note: Browser must be closed, and encrypted values
    require platform-specific decryption.

    Args:
        browser: 'chrome', 'firefox', 'edge', or 'chromium'
        domain: Domain filter

    Returns:
        Dict of cookie name → value
    """
    db_path = _find_cookie_db(browser)
    if not db_path:
        logger.warning(
            f"Could not find {browser} cookie database. "
            f"Export cookies using a browser extension instead."
        )
        return {}

    if browser == "firefox":
        return _read_firefox_cookies(db_path, domain)
    else:
        return _read_chromium_cookies(db_path, domain)


def _find_cookie_db(browser: str) -> Optional[Path]:
    """Find browser cookie database path."""
    import platform
    system = platform.system()

    if system == "Windows":
        local = Path.home() / "AppData" / "Local"
        roaming = Path.home() / "AppData" / "Roaming"

        paths = {
            "chrome": local / "Google" / "Chrome" / "User Data" / "Default" / "Cookies",
            "edge": local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies",
            "chromium": local / "Chromium" / "User Data" / "Default" / "Cookies",
            "firefox": None,  # Firefox uses profiles
        }

        if browser == "firefox":
            profiles_dir = roaming / "Mozilla" / "Firefox" / "Profiles"
            if profiles_dir.exists():
                for profile in profiles_dir.iterdir():
                    cookies_db = profile / "cookies.sqlite"
                    if cookies_db.exists():
                        return cookies_db

        path = paths.get(browser)
        if path and path.exists():
            return path

    elif system == "Darwin":  # macOS
        paths = {
            "chrome": Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Cookies",
            "edge": Path.home() / "Library" / "Application Support" / "Microsoft Edge" / "Default" / "Cookies",
            "chromium": Path.home() / "Library" / "Application Support" / "Chromium" / "Default" / "Cookies",
            "firefox": None,
        }

        if browser == "firefox":
            profiles_dir = Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles"
            if profiles_dir.exists():
                for profile in profiles_dir.iterdir():
                    cookies_db = profile / "cookies.sqlite"
                    if cookies_db.exists():
                        return cookies_db

        path = paths.get(browser)
        if path and path.exists():
            return path

    elif system == "Linux":
        paths = {
            "chrome": Path.home() / ".config" / "google-chrome" / "Default" / "Cookies",
            "chromium": Path.home() / ".config" / "chromium" / "Default" / "Cookies",
            "edge": Path.home() / ".config" / "microsoft-edge" / "Default" / "Cookies",
            "firefox": None,
        }

        if browser == "firefox":
            profiles_dir = Path.home() / ".mozilla" / "firefox"
            if profiles_dir.exists():
                for profile in profiles_dir.iterdir():
                    cookies_db = profile / "cookies.sqlite"
                    if cookies_db.exists():
                        return cookies_db

        path = paths.get(browser)
        if path and path.exists():
            return path

    return None


def _read_firefox_cookies(
    db_path: Path,
    domain: str = "",
) -> dict[str, str]:
    """Read cookies from Firefox SQLite database."""
    cookies = {}

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        if domain:
            cursor.execute(
                "SELECT name, value FROM moz_cookies WHERE host LIKE ?",
                (f"%{domain}%",)
            )
        else:
            cursor.execute("SELECT name, value FROM moz_cookies")

        for name, value in cursor.fetchall():
            if name:
                cookies[name] = value or ""

    except sqlite3.Error as e:
        logger.warning(
            f"Could not read Firefox cookies: {e}. "
            f"Make sure Firefox is closed."
        )
    finally:
        if conn:
            conn.close()

    return cookies


def _read_chromium_cookies(
    db_path: Path,
    domain: str = "",
) -> dict[str, str]:
    """
    Read cookies from Chromium-based browser SQLite database.

    Note: Chromium encrypts cookie values. This function reads
    unencrypted values only (value column). For encrypted values,
    use a browser extension to export cookies as JSON.
    """
    cookies = {}

    try:
        # Copy DB to avoid locking issues
        import shutil
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            shutil.copy2(db_path, tmp_path)

            conn = None
            try:
                conn = sqlite3.connect(str(tmp_path))
                cursor = conn.cursor()

                # Try to read unencrypted values
                if domain:
                    cursor.execute(
                        "SELECT name, value FROM cookies WHERE host_key LIKE ?",
                        (f"%{domain}%",)
                    )
                else:
                    cursor.execute("SELECT name, value FROM cookies")

                for name, value in cursor.fetchall():
                    if name:
                        cookies[name] = value or ""

                if not cookies:
                    logger.info(
                        "Chrome cookies are encrypted. "
                        "Export cookies using EditThisCookie or Cookie-Editor extension, "
                        "then use --cookies-file with the exported JSON."
                    )

            except sqlite3.Error as e:
                logger.warning(f"Could not read Chromium cookies: {e}")
            finally:
                if conn:
                    conn.close()
        finally:
            tmp_path.unlink(missing_ok=True)

    except Exception as e:
        logger.warning(f"Could not read Chromium cookies: {e}")

    return cookies


def _domain_matches(cookie_domain: str, target_domain: str) -> bool:
    """Check if cookie domain matches target domain."""
    # Remove leading dot and normalize case (domains are case-insensitive)
    cookie_domain = cookie_domain.lstrip(".").lower()
    target_domain = target_domain.lstrip(".").lower()

    # Exact match
    if cookie_domain == target_domain:
        return True

    # Subdomain match: target is subdomain of cookie domain
    if target_domain.endswith(f".{cookie_domain}"):
        return True

    # Reverse match: cookie is subdomain of target domain
    if cookie_domain.endswith(f".{target_domain}"):
        return True

    return False
