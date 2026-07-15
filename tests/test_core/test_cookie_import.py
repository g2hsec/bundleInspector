"""Netscape/curl cookie import must not silently drop HttpOnly cookies (curl/wget serialize them
with a literal `#HttpOnly_` prefix on the domain field). Those are exactly the session/auth cookies
an authenticated scan needs."""

from bundleInspector.core.cookie_import import import_cookies_from_file, parse_netscape_cookies


def test_netscape_parser_keeps_httponly_cookies():
    content = (
        "# Netscape HTTP Cookie File\n"
        "#HttpOnly_example.com\tFALSE\t/\tTRUE\t0\tSESSIONID\tsecret123\n"
        "example.com\tFALSE\t/\tFALSE\t0\ttheme\tdark\n"
    )
    assert parse_netscape_cookies(content) == {"SESSIONID": "secret123", "theme": "dark"}


def test_file_of_only_httponly_cookies_is_detected_as_netscape(tmp_path):
    """A jar of ONLY HttpOnly cookies must still be detected as Netscape format (the tab-field
    detector unwraps the marker) -- else the import silently returns nothing."""
    jar = tmp_path / "cookies.txt"
    jar.write_text(
        "#HttpOnly_example.com\tFALSE\t/\tTRUE\t0\tSESSIONID\tsecret123\n", encoding="utf-8"
    )
    assert import_cookies_from_file(jar) == {"SESSIONID": "secret123"}


def test_netscape_parser_still_skips_real_comments():
    """A genuine comment line is still ignored (no regression from the #HttpOnly_ unwrap)."""
    content = (
        "# Netscape HTTP Cookie File\n"
        "# this is a normal comment\n"
        "example.com\tFALSE\t/\tFALSE\t0\ttheme\tdark\n"
    )
    assert parse_netscape_cookies(content) == {"theme": "dark"}
