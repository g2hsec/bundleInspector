"""Regression tests for static collection MIME/base/dependency contracts."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from bundleInspector.collector import static as static_module
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import StaticCollector
from bundleInspector.config import AuthConfig, CrawlerConfig, ScopeConfig, ThirdPartyPolicy
from bundleInspector.core.rate_limiter import RateLimiter
from bundleInspector.storage.models import LoadMethod


class _Response:
    def __init__(self, text: str, content_type: str, url: str):
        self.status_code = 200
        self.text = text
        self.headers = {"content-type": content_type}
        self.url = url

    def raise_for_status(self) -> None:
        return None


class _Client:
    def __init__(self, response: _Response):
        self.response = response
        self.calls: list[str] = []

    async def get(self, url: str) -> _Response:
        self.calls.append(url)
        return self.response


def _scope() -> ScopePolicy:
    return ScopePolicy(ScopeConfig(third_party_policy=ThirdPartyPolicy.ANALYZE))


async def test_static_collector_sniffs_generic_html_and_uses_final_url_and_first_valid_base():
    html = """
    <!doctype html><html><head>
      <base href="javascript:alert(1)">
      <base href="https://cdn.example.net/assets/">
      <base href="https://ignored.example.net/">
      <script src="app.js"></script>
      <link rel="modulepreload" href="chunk.js">
      <script type="module">import(`./lazy.js`);</script>
    </head></html>
    """
    response = _Response(
        html,
        "text/plain; charset=utf-8",
        "https://example.com/final/index.html",
    )
    collector = StaticCollector(CrawlerConfig())
    collector._client = _Client(response)

    refs = [ref async for ref in collector.collect("https://example.com/start", _scope())]
    by_method = {(ref.method, ref.url): ref for ref in refs}

    assert (LoadMethod.SCRIPT_TAG, "https://cdn.example.net/assets/app.js") in by_method
    assert (LoadMethod.MODULE_PRELOAD, "https://cdn.example.net/assets/chunk.js") in by_method
    dynamic = by_method[(LoadMethod.DYNAMIC_IMPORT, "https://cdn.example.net/assets/lazy.js")]
    assert dynamic.initiator == "https://example.com/final/index.html"
    assert dynamic.load_context == "https://example.com/final/index.html"
    assert all("ignored.example.net" not in ref.url for ref in refs)


async def test_static_collector_does_not_sniff_explicit_json_as_html():
    response = _Response(
        '<html><script src="/false-positive.js"></script></html>',
        "application/json",
        "https://example.com/data",
    )
    collector = StaticCollector(CrawlerConfig())
    collector._client = _Client(response)

    assert [ref async for ref in collector.collect("https://example.com/data", _scope())] == []


async def test_dependency_scanner_excludes_comments_strings_templates_and_regex_bodies():
    source = r'''
      // import("./comment.js")
      /* require('./block-comment.js') */
      const example = "import('./string.js')";
      const templateExample = `require("./template-text.js")`;
      const matcher = /import\(["']\.\/regex\.js/;
      import(`./real-template.js`);
      require.ensure([], function (require) { require("./ensured.js"); });
    '''
    collector = StaticCollector(CrawlerConfig())

    refs = [
        ref
        async for ref in collector._extract_dynamic_imports(
            source,
            "https://example.com/static/app.js",
            _scope(),
        )
    ]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/real-template.js",
        "https://example.com/static/ensured.js",
    ]


async def test_dependency_scanner_includes_static_import_from_in_source_order():
    collector = StaticCollector(CrawlerConfig())
    source = 'import "./setup.js"; import value from "./value.js"; export {x} from "./x.js";'

    refs = [
        ref
        async for ref in collector._extract_dynamic_imports(
            source,
            "https://example.com/app.js",
            _scope(),
        )
    ]

    assert [ref.url for ref in refs] == [
        "https://example.com/setup.js",
        "https://example.com/value.js",
        "https://example.com/x.js",
    ]


@pytest.mark.asyncio
async def test_static_setup_uses_pinned_transport_without_global_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    transport = object()

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            return None

    def build_transport(*, allow_private_ips: bool, max_connections: int) -> object:
        captured["transport_policy"] = (allow_private_ips, max_connections)
        return transport

    monkeypatch.setattr(static_module.httpx, "AsyncClient", Client)
    monkeypatch.setattr(static_module, "build_pinned_transport", build_transport)
    collector = StaticCollector(
        CrawlerConfig(max_concurrent=7),
        AuthConfig(bearer_token="secret", cookies={"sid": "cookie"}),
        allow_private_ips=True,
    )

    await collector.setup()

    assert captured["transport"] is transport
    assert captured["transport_policy"] == (True, 7)
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False
    assert "cookies" not in captured
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers


def test_static_auth_headers_require_exact_normalized_origin() -> None:
    collector = StaticCollector(
        CrawlerConfig(),
        AuthConfig(headers={"X-Scan": "secret"}, bearer_token="token"),
    )
    collector._bind_auth_origin("https://victim.co.uk/root")

    assert collector._request_headers("https://victim.co.uk:443/next") == {
        "X-Scan": "secret",
        "Authorization": "Bearer token",
    }
    for url in (
        "https://attacker.co.uk/",
        "https://sub.victim.co.uk/",
        "https://victim.co.uk:8443/",
        "http://victim.co.uk/",
    ):
        assert collector._request_headers(url) == {}


@pytest.mark.asyncio
async def test_static_manual_redirect_strips_auth_and_uses_shared_limiter() -> None:
    calls: list[tuple[str, dict[str, str]]] = []
    limited: list[str] = []

    class Client:
        async def get(
            self,
            url: str,
            headers: dict[str, str] | None = None,
        ) -> httpx.Response:
            calls.append((url, dict(headers or {})))
            request = httpx.Request("GET", url, headers=headers)
            if len(calls) == 1:
                return httpx.Response(
                    302,
                    headers={"location": "https://attacker.co.uk/landing"},
                    request=request,
                )
            return httpx.Response(
                200,
                text="<html></html>",
                headers={"content-type": "text/html"},
                request=request,
            )

    class Limiter(RateLimiter):
        async def acquire(self, url: str) -> None:
            limited.append(url)

    collector = StaticCollector(
        CrawlerConfig(),
        AuthConfig(
            headers={"X-Scan": "secret"},
            bearer_token="token",
            cookies={"sid": "cookie"},
        ),
        rate_limiter=Limiter(),
    )
    collector._client = Client()

    refs = [
        ref
        async for ref in collector.collect(
            "https://victim.co.uk/root",
            _scope(),
        )
    ]

    assert refs == []
    assert calls[0][1] == {
        "X-Scan": "secret",
        "Authorization": "Bearer token",
        "Cookie": "sid=cookie",
    }
    assert calls[1][1] == {}
    assert limited == ["https://victim.co.uk/root", "https://attacker.co.uk/landing"]


@pytest.mark.asyncio
async def test_static_redirect_to_metadata_is_blocked_before_second_request() -> None:
    calls: list[str] = []

    class Client:
        async def get(self, url: str) -> httpx.Response:
            calls.append(url)
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
                request=httpx.Request("GET", url),
            )

    collector = StaticCollector(CrawlerConfig())
    collector._client = Client()

    assert [
        ref
        async for ref in collector.collect(
            "https://example.com/root",
            _scope(),
        )
    ] == []
    assert calls == ["https://example.com/root"]


def test_dependency_lexer_handles_template_interpolation_and_control_header_regex() -> None:
    assert list(static_module._iter_static_dependencies(
        'const s=`x${import("./real.js")}`;'
    )) == ["./real.js"]
    assert list(static_module._iter_static_dependencies(
        'const s=`x${`import("./runtime.js")`} tail`; import("./real.js")'
    )) == ["./real.js"]
    assert list(static_module._iter_static_dependencies(
        'if(x) /import(".\\/fake.js")/.test(s); import("./real.js")'
    )) == ["./real.js"]


@pytest.mark.parametrize("line_terminator", ["\n", "\r", "\u2028", "\u2029"])
def test_dependency_lexer_skips_regex_after_statement_block(
    line_terminator: str,
) -> None:
    source = f'if(ok) {{}}{line_terminator}/import(".\\/fake.js")/.test(x)'

    assert list(static_module._iter_static_dependencies(source)) == []
    comment = f'// import("./fake.js"){line_terminator}import("./real.js")'
    assert list(static_module._iter_static_dependencies(comment)) == ["./real.js"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('const value = {a: 1} / import("./object.js")', "./object.js"),
        ('const value = function () {} / import("./function.js")', "./function.js"),
        ('const value = class {} / import("./class.js")', "./class.js"),
    ],
)
def test_dependency_lexer_preserves_division_after_expression_braces(
    source: str,
    expected: str,
) -> None:
    assert list(static_module._iter_static_dependencies(source)) == [expected]


@pytest.mark.parametrize(
    "source",
    [
        'if (ok) { const value = {}; }\n/import(".\\/if-fake.js")/.test(x)',
        'while (ok) {}\n/import(".\\/while-fake.js")/.test(x)',
        'for (;;) {}\n/import(".\\/for-fake.js")/.test(x)',
        'with (value) {}\n/import(".\\/with-fake.js")/.test(x)',
        'switch (value) {}\n/import(".\\/switch-fake.js")/.test(x)',
        'try {} catch (error) {} finally {}\n/import(".\\/try-fake.js")/.test(x)',
        'do {} while (ok);\n/import(".\\/do-fake.js")/.test(x)',
        'function declared() {}\n/import(".\\/function-fake.js")/.test(x)',
        'async function declared() {}\n/import(".\\/async-function-fake.js")/.test(x)',
        'class Declared {}\n/import(".\\/class-fake.js")/.test(x)',
        'export default class Declared {}\n/import(".\\/export-class-fake.js")/.test(x)',
    ],
)
def test_dependency_lexer_skips_regex_after_statement_body(source: str) -> None:
    assert list(static_module._iter_static_dependencies(source)) == []


@pytest.mark.asyncio
async def test_static_retries_transient_status_and_bounds_response_body() -> None:
    class RetryClient:
        def __init__(self):
            self.calls = 0

        async def get(self, url: str) -> httpx.Response:
            self.calls += 1
            status = 503 if self.calls == 1 else 200
            body = b"" if status == 503 else b'<script src="/app.js"></script>'
            return httpx.Response(
                status,
                content=body,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    config = CrawlerConfig(max_retries=1, retry_delay=0, max_file_size=1024)
    collector = StaticCollector(config)
    client = RetryClient()
    collector._client = client
    refs = [ref async for ref in collector.collect("https://example.com/", _scope())]
    assert [ref.url for ref in refs] == ["https://example.com/app.js"]
    assert client.calls == 2

    class OversizedClient:
        async def get(self, url: str) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"x" * 33,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    bounded = StaticCollector(CrawlerConfig(max_retries=3, max_file_size=32))
    bounded._client = OversizedClient()
    assert [ref async for ref in bounded.collect("https://example.com/", _scope())] == []
    assert bounded.retryable_failures == []
