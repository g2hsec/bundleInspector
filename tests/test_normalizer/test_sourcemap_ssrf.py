"""SSRF guard for external sourcemap fetching: a `sourceMappingURL` in the scanned JS is
attacker-controlled, so the resolver must validate it against is_url_safe before any egress and
degrade to "no sourcemap" (None) on block -- while inline data: maps and public CDNs are unaffected.
"""

import base64
import json
from urllib.parse import quote

from bundleInspector.core.rate_limiter import RateLimiter
from bundleInspector.normalizer.sourcemap import SourceMapInfo, SourceMapResolver

_VALID_MAP = '{"version":3,"sources":["a.js"],"sourcesContent":["x"],"mappings":"AAAA"}'


class _StubResp:
    def __init__(self, text, status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


class _StubClient:
    """Records every .get() so a test can prove the network was (not) reached."""

    def __init__(self, text=_VALID_MAP):
        self.calls: list[str] = []
        self._text = text

    async def get(self, url):
        self.calls.append(url)
        return _StubResp(self._text)

    async def aclose(self):
        pass


class _RedirectClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, url):
        self.calls.append(url)
        return self.responses[url]


async def test_fetch_sourcemap_blocks_cloud_metadata_ip():
    r = SourceMapResolver()
    r._client = _StubClient()
    assert await r._fetch_sourcemap("http://169.254.169.254/latest/meta-data/app.js.map") is None
    assert r._client.calls == []  # blocked before any egress


async def test_fetch_sourcemap_blocks_loopback_and_private_by_default():
    for url in ("http://127.0.0.1/app.js.map", "http://10.0.0.5/app.js.map"):
        r = SourceMapResolver()
        r._client = _StubClient()
        assert await r._fetch_sourcemap(url) is None
        assert r._client.calls == []


async def test_fetch_sourcemap_allows_public(monkeypatch):
    """A public (safe) host must still be fetched -- the guard blocks only unsafe hosts."""
    import bundleInspector.core.security as sec
    monkeypatch.setattr(sec, "is_url_safe", lambda *a, **k: (True, "OK"))
    r = SourceMapResolver()
    r._client = _StubClient()
    out = await r._fetch_sourcemap("https://cdn.example.com/app.js.map")
    assert isinstance(out, SourceMapInfo)
    assert r._client.calls == ["https://cdn.example.com/app.js.map"]


async def test_allow_private_ips_permits_private_sourcemap():
    """Authorized internal scanning (allow_private_ips=True) keeps fetching private-host maps,
    mirroring how the download path already treats private JS hosts."""
    r = SourceMapResolver(allow_private_ips=True)
    r._client = _StubClient()
    out = await r._fetch_sourcemap("http://10.0.0.5/app.js.map")
    assert isinstance(out, SourceMapInfo)
    assert r._client.calls == ["http://10.0.0.5/app.js.map"]


async def test_resolve_external_ssrf_blocked_degrades_to_none():
    r = SourceMapResolver()
    r._client = _StubClient()
    js = "x=1;\n//# sourceMappingURL=http://127.0.0.1/app.js.map"
    assert await r.resolve(js, "https://example.com/app.js") is None
    assert r._client.calls == []
    assert r.last_diagnostic.status == "failed"
    assert r.last_diagnostic.reason == "unsafe_url"
    assert "127.0.0.1" in (r.last_diagnostic.reference or "")
    assert "app.js.map" not in (r.last_diagnostic.reference or "")


async def test_fetch_sourcemap_revalidates_redirect_target_before_second_egress(monkeypatch):
    import bundleInspector.core.security as sec

    monkeypatch.setattr(
        sec,
        "is_url_safe",
        lambda url, *_args: (not url.startswith("http://127.0.0.1"), "test policy"),
    )
    start = "https://cdn.example.com/app.js.map"
    client = _RedirectClient({
        start: _StubResp("", status=302, headers={"location": "http://127.0.0.1/private.map"}),
    })
    resolver = SourceMapResolver()
    resolver._client = client

    assert await resolver._fetch_sourcemap(start) is None
    assert client.calls == [start]
    assert resolver.last_diagnostic.reason == "unsafe_redirect"


async def test_fetch_sourcemap_follows_bounded_safe_redirect_and_records_final_url(monkeypatch):
    import bundleInspector.core.security as sec

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    start = "https://cdn.example.com/app.js.map"
    final = "https://assets.example.com/maps/app.js.map"
    client = _RedirectClient({
        start: _StubResp("", status=307, headers={"location": final}),
        final: _StubResp(_VALID_MAP),
    })
    resolver = SourceMapResolver()
    resolver._client = client

    result = await resolver._fetch_sourcemap(start)

    assert isinstance(result, SourceMapInfo)
    assert result.url == final
    assert client.calls == [start, final]


async def test_resolve_inline_data_uri_bypasses_the_gate():
    """Inline (data:) maps carry their own content and never hit the network, so the SSRF gate must
    not be consulted and the map must still parse."""
    r = SourceMapResolver()
    r._client = _StubClient()
    m = base64.b64encode(_VALID_MAP.encode()).decode()
    js = f"x=1;\n//# sourceMappingURL=data:application/json;base64,{m}"
    out = await r.resolve(js, "https://example.com/app.js")
    assert isinstance(out, SourceMapInfo) and out.is_inline
    assert r._client.calls == []
    assert r.last_diagnostic.status == "resolved"


async def test_resolve_distinguishes_absent_and_malformed_inline_map():
    resolver = SourceMapResolver()

    assert await resolver.resolve("const x = 1;", "https://example.com/app.js") is None
    assert resolver.last_diagnostic.status == "not_found"
    assert resolver.last_diagnostic.discovered is False

    js = "x=1;\n//# sourceMappingURL=data:application/json;base64,not-base64"
    assert await resolver.resolve(js, "https://example.com/app.js") is None
    assert resolver.last_diagnostic.status == "failed"
    assert resolver.last_diagnostic.discovered is True
    assert resolver.last_diagnostic.reason == "inline_decode_or_parse_error"


def test_resolver_noarg_ctor_defaults_allow_private_false():
    """Backward-compat: the no-arg constructor (asset_analyzer / offline callers) still works."""
    assert SourceMapResolver().allow_private_ips is False


async def test_urlencoded_inline_map_is_supported_and_size_capped():
    content = json.dumps({
        "version": 3,
        "sourceRoot": "/src",
        "sources": ["entry.ts"],
        "sourcesContent": ["export const value = 1;"],
        "mappings": "AAAA",
    })
    resolver = SourceMapResolver()
    js = (
        "x=1;\n//# sourceMappingURL=data:application/json;charset=utf-8,"
        + quote(content, safe="")
    )

    result = await resolver.resolve(js, "https://example.com/app.js")

    assert isinstance(result, SourceMapInfo)
    assert resolver.last_diagnostic.status == "resolved"
    assert resolver.get_original_sources(result) == {
        "/src/entry.ts": "export const value = 1;"
    }

    resolver.MAX_SOURCEMAP_BYTES = 8
    assert await resolver.resolve(js, "https://example.com/app.js") is None
    assert resolver.last_diagnostic.reason == "inline_decode_or_parse_error"


def test_source_root_resolution_contains_traversal_and_cross_origin_sources():
    resolver = SourceMapResolver()
    source_map = resolver._parse_sourcemap_json(
        json.dumps({
            "version": 3,
            "sourceRoot": "https://cdn.example.com/maps/src/",
            "sources": ["entry.ts", "../escape.ts", "https://evil.example/x.ts"],
            "sourcesContent": ["entry", "escape", "evil"],
            "mappings": "AAAA",
        }),
        is_inline=False,
        url="https://cdn.example.com/maps/app.js.map",
    )

    assert isinstance(source_map, SourceMapInfo)
    originals = resolver.get_original_sources(source_map)
    assert originals["https://cdn.example.com/maps/src/entry.ts"] == "entry"
    encoded = json.dumps(originals)
    assert "escape.ts" not in encoded
    assert "evil.example" not in encoded
    assert encoded.count("[escaped-source:") == 2
    position = resolver.get_original_position(source_map, 1, 0)
    assert position is not None
    assert position.source == "https://cdn.example.com/maps/src/entry.ts"


def test_indexed_sections_preserve_offsets_sources_and_checkpoint_shape():
    resolver = SourceMapResolver()
    source_map = resolver._parse_sourcemap_json(
        json.dumps({
            "version": 3,
            "sections": [
                {
                    "offset": {"line": 2, "column": 5},
                    "map": {
                        "version": 3,
                        "sourceRoot": "/src",
                        "sources": ["first.ts"],
                        "sourcesContent": ["first"],
                        "mappings": "AAAA",
                    },
                },
                {
                    "offset": {"line": 4, "column": 0},
                    "map": {
                        "version": 3,
                        "sourceRoot": "/src",
                        "sources": ["second.ts"],
                        "sourcesContent": ["second"],
                        "mappings": "AAAA",
                    },
                },
            ],
        }),
        is_inline=True,
    )

    assert isinstance(source_map, SourceMapInfo)
    assert resolver.get_original_position(source_map, 3, 4) is None
    first = resolver.get_original_position(source_map, 3, 5)
    second = resolver.get_original_position(source_map, 5, 0)
    assert first is not None and (first.source, first.line, first.column) == (
        "/src/first.ts",
        1,
        0,
    )
    assert second is not None and second.source == "/src/second.ts"
    assert resolver.get_original_sources(source_map) == {
        "/src/first.ts": "first",
        "/src/second.ts": "second",
    }
    restored = SourceMapInfo.from_dict(source_map.to_dict())
    restored_first = resolver.get_original_position(restored, 3, 5)
    assert restored_first is not None and restored_first.source == "/src/first.ts"


async def test_malformed_indexed_map_has_bounded_failure_diagnostic():
    malformed = quote(json.dumps({
        "version": 3,
        "sections": [
            {"offset": {"line": 1, "column": 0}, "map": {"version": 3}},
            {"offset": {"line": 0, "column": 0}, "map": {"version": 3}},
        ],
    }), safe="")
    resolver = SourceMapResolver()
    js = f"x=1;\n//# sourceMappingURL=data:application/json,{malformed}"

    assert await resolver.resolve(js, "https://example.com/app.js") is None
    assert resolver.last_diagnostic.status == "failed"
    assert resolver.last_diagnostic.reason == "inline_decode_or_parse_error"
    assert len(resolver.last_diagnostic.reference or "") < 100


async def test_setup_uses_pinned_transport_and_disables_environment_proxy(monkeypatch):
    import httpx

    sentinel = object()
    captured: dict[str, object] = {}

    class Client:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def aclose(self):
            return None

    def transport(**kwargs):
        captured["transport_args"] = kwargs
        return sentinel

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    monkeypatch.setattr("bundleInspector.core.safe_http.build_pinned_transport", transport)
    resolver = SourceMapResolver(allow_private_ips=True)

    await resolver.setup()

    assert captured["transport"] is sentinel
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
    assert captured["transport_args"] == {"allow_private_ips": True, "max_connections": 1}


async def test_every_redirect_hop_uses_shared_request_budget(monkeypatch):
    class Budget(RateLimiter):
        def __init__(self):
            super().__init__(interval=0, max_concurrent=1)
            self.acquired: list[str] = []
            self.slots = 0
            self.releases = 0

        async def acquire(self, url: str = "") -> None:
            self.acquired.append(url)

        async def acquire_slot(self) -> None:
            self.slots += 1

        def release_slot(self) -> None:
            self.releases += 1

    import bundleInspector.core.security as sec

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    start = "https://cdn.example.com/app.js.map"
    final = "https://cdn.example.com/final.js.map"
    client = _RedirectClient({
        start: _StubResp("", status=302, headers={"location": final}),
        final: _StubResp(_VALID_MAP),
    })
    budget = Budget()
    resolver = SourceMapResolver(rate_limiter=budget)
    resolver._client = client

    assert isinstance(await resolver._fetch_sourcemap(start), SourceMapInfo)
    assert budget.acquired == [start, final]
    assert budget.slots == budget.releases == 2


def test_parse_content_uses_no_network_and_records_bounded_diagnostic():
    resolver = SourceMapResolver()

    result = resolver.parse_content(
        _VALID_MAP,
        url="file:///C:/Users/alice/project/app.js.map",
    )

    assert isinstance(result, SourceMapInfo)
    assert resolver._client is None
    assert resolver.last_diagnostic.status == "resolved"
    assert "alice" not in (resolver.last_diagnostic.reference or "")

    assert resolver.parse_content("not-json", url="file:///secret/map") is None
    assert resolver.last_diagnostic.reason == "malformed_sourcemap"


async def test_sourcemap_auth_is_exact_origin_and_stripped_on_redirect(monkeypatch):
    import bundleInspector.core.security as sec
    from bundleInspector.core.safe_http import normalized_origin, origin_bound_auth_headers

    start = "https://app.example.com/app.js.map"
    redirected = "https://cdn.example.com/app.js.map"
    origin = normalized_origin("https://app.example.com/index.html")
    assert origin is not None

    def headers(url: str):
        return origin_bound_auth_headers(
            url,
            {origin},
            {
                "Authorization": "Bearer AUTH_CANARY",
                "Host": "attacker.example",
                "Cookie": "injected=COOKIE_CANARY",
            },
            {"session": "SESSION_CANARY"},
        )

    class Client:
        def __init__(self):
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def get(self, url: str, headers=None):
            self.calls.append((url, dict(headers or {})))
            if url == start:
                return _StubResp("", status=302, headers={"location": redirected})
            return _StubResp(_VALID_MAP)

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    client = Client()
    resolver = SourceMapResolver(headers_for_url=headers)
    resolver._client = client

    assert isinstance(await resolver._fetch_sourcemap(start), SourceMapInfo)
    assert client.calls[0] == (
        start,
        {
            "Authorization": "Bearer AUTH_CANARY",
            "Cookie": "session=SESSION_CANARY",
        },
    )
    assert client.calls[1] == (redirected, {})


async def test_sourcemap_auth_failure_is_structured_without_response_body(monkeypatch):
    import bundleInspector.core.security as sec

    class Client:
        async def get(self, _url: str, **_kwargs):
            return _StubResp("AUTH_FAILURE_BODY_CANARY", status=401)

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    resolver = SourceMapResolver(headers_for_url=lambda _url: {"Authorization": "secret"})
    resolver._client = Client()

    assert await resolver._fetch_sourcemap("https://app.example.com/app.js.map") is None
    assert resolver.last_diagnostic.reason == "http_status"
    assert resolver.last_diagnostic.http_status == 401
    assert "AUTH_FAILURE_BODY_CANARY" not in repr(resolver.last_diagnostic)


async def test_external_sourcemap_stream_is_capped_before_full_body_buffer(monkeypatch):
    import bundleInspector.core.security as sec

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self):
            self.chunks_read = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            for chunk in (b"1234", b"5678", b"must-not-be-read"):
                self.chunks_read += 1
                yield chunk

    class Client:
        def __init__(self):
            self.response = Response()

        def stream(self, _method: str, _url: str, **_kwargs):
            return self.response

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    client = Client()
    resolver = SourceMapResolver()
    resolver.MAX_SOURCEMAP_BYTES = 5
    resolver._client = client

    assert await resolver._fetch_sourcemap("https://cdn.example.com/app.js.map") is None
    assert resolver.last_diagnostic.reason == "response_too_large"
    assert client.response.chunks_read == 2


async def test_scope_rejection_precedes_source_map_network_egress(monkeypatch):
    import bundleInspector.core.security as sec

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    client = _StubClient()
    resolver = SourceMapResolver(is_allowed=lambda _url: False)
    resolver._client = client

    assert await resolver._fetch_sourcemap("https://cdn.example.com/app.js.map") is None
    assert client.calls == []
    assert resolver.last_diagnostic.reason == "out_of_scope_url"


async def test_scope_rejection_blocks_redirect_before_second_egress(monkeypatch):
    import bundleInspector.core.security as sec

    start = "https://cdn.example.com/app.js.map"
    redirected = "https://attacker.example/secret.map"
    client = _RedirectClient({
        start: _StubResp("", status=302, headers={"location": redirected}),
    })
    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    resolver = SourceMapResolver(is_allowed=lambda url: url == start)
    resolver._client = client

    assert await resolver._fetch_sourcemap(start) is None
    assert client.calls == [start]
    assert resolver.last_diagnostic.reason == "out_of_scope_redirect"


async def test_comment_aware_directive_scan_ignores_template_decoy_and_contains_bad_url():
    resolver = SourceMapResolver()
    content = (
        "const decoy = `//# sourceMappingURL=https://attacker.example/evil.map`;\r\n"
        "//# sourceMappingURL=good.map   \r\n"
    )
    assert resolver.find_sourcemap_url(content) == "good.map"

    resolver._client = _StubClient()
    assert await resolver.resolve("//# sourceMappingURL=//[bad", "https://example.com/app.js") is None
    assert resolver._client.calls == []
    assert resolver.last_diagnostic.reason == "invalid_sourcemap_url"


def test_duplicate_resolved_source_paths_keep_distinct_content_order_independently():
    resolver = SourceMapResolver()

    def originals(contents: list[str]) -> dict[str, str]:
        source_map = SourceMapInfo(
            url="https://example.com/app.js.map",
            content=None,
            is_inline=False,
            sources=["src/a.js", "src/./a.js"],
            sources_content=contents,
            mappings="",
        )
        return resolver.get_original_sources(source_map)

    first = originals(["fetch('/api/first')", "fetch('/api/second')"])
    second = originals(["fetch('/api/second')", "fetch('/api/first')"])
    assert set(first.values()) == {"fetch('/api/first')", "fetch('/api/second')"}
    assert first == second


def test_pathological_vlq_value_is_bounded_and_observable():
    resolver = SourceMapResolver()
    source_map = resolver.parse_content(
        json.dumps({
            "version": 3,
            "sources": ["a.js"],
            "sourcesContent": ["x"],
            "mappings": "/" * 100_000,
        }),
    )
    assert source_map is not None
    assert source_map.diagnostics == ["vlq_value_too_long"]
    assert resolver.decode_mappings(source_map) == [[]]


async def test_source_map_retries_transient_status(monkeypatch):
    import bundleInspector.core.security as sec

    class Client:
        def __init__(self):
            self.calls = 0

        async def get(self, _url):
            self.calls += 1
            if self.calls == 1:
                return _StubResp("", status=503)
            return _StubResp(_VALID_MAP)

    class Limiter:
        def __init__(self):
            self.acquired: list[str] = []
            self.slots = 0
            self.released = 0

        async def acquire(self, url: str) -> None:
            self.acquired.append(url)

        async def acquire_slot(self) -> None:
            self.slots += 1

        def release_slot(self) -> None:
            self.released += 1

    monkeypatch.setattr(sec, "is_url_safe", lambda *_args: (True, "OK"))
    client = Client()
    limiter = Limiter()
    resolver = SourceMapResolver(
        max_retries=1,
        retry_delay=0,
        rate_limiter=limiter,
    )
    resolver._client = client
    assert await resolver._fetch_sourcemap("https://cdn.example.com/app.js.map") is not None
    assert client.calls == 2
    assert len(limiter.acquired) == limiter.slots == limiter.released == 2
