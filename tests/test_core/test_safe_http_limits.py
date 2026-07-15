"""Response-budget and resolver-deadline regressions for the pinned HTTP transport."""

from __future__ import annotations

import asyncio
import time

import pytest

from bundleInspector.core import safe_http


class _StreamResponse:
    def __init__(self, status: int, chunks: list[bytes], *, location: str | None = None):
        self.status_code = status
        self.headers = {"location": location} if location else {}
        self.extensions: dict[str, object] = {}
        self._chunks = chunks
        self.chunks_read = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def aiter_bytes(self):
        for chunk in self._chunks:
            self.chunks_read += 1
            yield chunk


class _StreamClient:
    def __init__(self, responses: list[_StreamResponse]):
        self.responses = responses
        self.calls: list[str] = []

    def stream(self, _method: str, url: str, **_kwargs):
        self.calls.append(url)
        return self.responses[len(self.calls) - 1]


@pytest.mark.asyncio
async def test_redirect_body_is_unread_and_final_decoded_body_is_capped(monkeypatch) -> None:
    monkeypatch.setattr(safe_http, "is_url_safe", lambda *_args, **_kwargs: (True, "OK"))
    redirect = _StreamResponse(302, [b"redirect-body"], location="/final")
    final = _StreamResponse(200, [b"1234", b"5678"])
    client = _StreamClient([redirect, final])

    with pytest.raises(safe_http.ResponseTooLarge):
        await safe_http.get_with_safe_redirects(
            client,
            "https://example.com/start",
            allow_private_ips=False,
            follow_redirects=True,
            max_redirects=2,
            max_response_bytes=5,
        )

    assert client.calls == ["https://example.com/start", "https://example.com/final"]
    assert redirect.chunks_read == 0
    assert final.chunks_read == 2


@pytest.mark.asyncio
async def test_dns_resolution_obeys_timeout_without_unbounded_wait(monkeypatch) -> None:
    def slow_resolver(_host: str, _port: int, _allow_private: bool) -> list[str]:
        time.sleep(0.15)
        return ["203.0.113.10"]

    monkeypatch.setattr(safe_http, "_resolve_validated_addresses", slow_resolver)
    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        await safe_http.resolve_validated_addresses(
            "slow.example",
            443,
            False,
            timeout=0.01,
        )
    assert time.perf_counter() - started < 0.1
    # Let the non-cancellable resolver thread finish; its retained semaphore slot is released by
    # the worker callback rather than by the timed-out caller.
    await asyncio.sleep(0.2)
