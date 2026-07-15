"""HTTP transport primitives that bind DNS validation to the socket connection."""

from __future__ import annotations

import asyncio
import socket
import weakref
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping
from contextlib import suppress
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from bundleInspector.core.security import is_host_blocked, is_ip_blocked, is_url_safe

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_RESOLVER_WORKERS = 16
_MAX_RESOLVED_ADDRESSES = 8
_RESOLVER_SEMAPHORES: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, asyncio.Semaphore
] = weakref.WeakKeyDictionary()


class UnsafeNetworkTarget(httpcore.ConnectError):
    """Raised when a connection target violates the SSRF address policy."""


class UnsafeRequestTarget(httpx.RequestError):
    """Raised before a request when a URL or redirect hop violates request policy."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(
            f"blocked request target: {reason}",
            request=httpx.Request("GET", url),
        )


class ResponseTooLarge(httpx.RequestError):
    """Raised when a response exceeds its configured decoded-body budget."""

    def __init__(self, url: str, max_bytes: int):
        self.url = url
        self.max_bytes = max_bytes
        super().__init__(
            f"response body exceeds configured limit ({max_bytes} bytes)",
            request=httpx.Request("GET", url),
        )


def normalized_origin(url: str) -> tuple[str, str, int] | None:
    """Return an exact HTTP origin with IDNA host and effective default port."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except (TypeError, ValueError, UnicodeError):
        return None
    return scheme, host, port


def origin_bound_auth_headers(
    request_url: str,
    allowed_origins: Collection[tuple[str, str, int]],
    auth_headers: Mapping[str, str],
    cookies: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return configured credentials only for an exact normalized origin."""
    origin = normalized_origin(request_url)
    if origin is None or origin not in allowed_origins:
        return {}
    headers = {
        name: value
        for name, value in auth_headers.items()
        if name.lower() not in {"host", "content-length", "transfer-encoding", "cookie"}
    }
    if cookies:
        headers["Cookie"] = "; ".join(
            f"{name}={value}" for name, value in sorted(cookies.items())
        )
    return headers


async def get_with_safe_redirects(
    client: httpx.AsyncClient,
    url: str,
    *,
    allow_private_ips: bool,
    follow_redirects: bool,
    max_redirects: int,
    is_allowed: Callable[[str], bool] | None = None,
    headers_for_url: Callable[[str], Mapping[str, str]] | None = None,
    before_request: Callable[[str], Awaitable[None]] | None = None,
    max_response_bytes: int | None = None,
) -> httpx.Response:
    """GET one URL with validated manual redirect hops and per-origin credentials.

    URL syntax, blocked hostnames and IP literals are rejected before each request. Hostname DNS is
    deliberately validated by ``PinnedNetworkBackend`` at connect time, where the checked address
    is the address actually dialed; a separate preflight resolution would reintroduce a TOCTOU gap.
    """
    current_url = url
    redirect_count = 0
    while True:
        safe, reason = is_url_safe(
            current_url,
            resolve_dns=False,
            allow_private_ips=allow_private_ips,
        )
        if not safe:
            raise UnsafeRequestTarget(current_url, reason)
        if is_allowed is not None and not is_allowed(current_url):
            raise UnsafeRequestTarget(current_url, "URL is outside configured scope")
        if before_request is not None:
            await before_request(current_url)

        request_headers = dict(headers_for_url(current_url)) if headers_for_url else {}
        response = await _get_response(
            client,
            current_url,
            request_headers,
            max_response_bytes=max_response_bytes,
        )
        if response.status_code not in _REDIRECT_STATUS_CODES:
            return response
        location = response.headers.get("location")
        if not follow_redirects or not location:
            return response
        if redirect_count >= max(0, max_redirects):
            await response.aclose()
            raise httpx.TooManyRedirects(
                f"Exceeded maximum allowed redirects ({max_redirects})",
                request=httpx.Request("GET", current_url),
            )
        try:
            next_url = urljoin(current_url, location)
        except (TypeError, ValueError):
            await response.aclose()
            raise UnsafeRequestTarget(current_url, "redirect location is malformed") from None
        await response.aclose()
        current_url = next_url
        redirect_count += 1


async def _get_response(
    client: httpx.AsyncClient,
    url: str,
    headers: Mapping[str, str],
    *,
    max_response_bytes: int | None,
) -> httpx.Response:
    """Read a final response with a decoded-byte cap when streaming is available."""
    if max_response_bytes is None:
        return await client.get(url, headers=dict(headers)) if headers else await client.get(url)

    limit = max(0, int(max_response_bytes))
    stream = getattr(client, "stream", None)
    if callable(stream):
        kwargs = {"headers": dict(headers)} if headers else {}
        async with stream("GET", url, **kwargs) as response:
            if response.status_code in _REDIRECT_STATUS_CODES:
                # Redirect bodies are deliberately left unread. A detached response preserves the
                # status and headers after the streaming context closes.
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    request=httpx.Request("GET", url),
                )
            declared_length = response.headers.get("content-length")
            if declared_length is not None:
                with suppress(ValueError):
                    if int(declared_length) > limit:
                        raise ResponseTooLarge(url, limit)
            body = bytearray()
            chunks = response.aiter_bytes()
            try:
                async for chunk in chunks:
                    if len(body) + len(chunk) > limit:
                        raise ResponseTooLarge(url, limit)
                    body.extend(chunk)
            finally:
                close_chunks = getattr(chunks, "aclose", None)
                if callable(close_chunks):
                    await close_chunks()
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=bytes(body),
                request=httpx.Request("GET", url),
            )

    # Small test doubles and compatibility clients may only expose ``get``. The post-read check
    # preserves policy correctness, though production AsyncClient instances always stream above.
    response = await client.get(url, headers=dict(headers)) if headers else await client.get(url)
    content = getattr(response, "content", None)
    if content is None:
        content = str(getattr(response, "text", "") or "").encode("utf-8")
    if len(content) > limit:
        close = getattr(response, "aclose", None)
        if callable(close):
            await close()
        raise ResponseTooLarge(url, limit)
    return response


def _resolve_validated_addresses(host: str, port: int, allow_private_ips: bool) -> list[str]:
    """Resolve once, reject mixed safe/unsafe answers, and return a deterministic pinned set."""
    if is_host_blocked(host, allow_private_ips):
        raise UnsafeNetworkTarget(f"blocked connection host: {host}")
    try:
        answers = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeNetworkTarget(f"unable to resolve connection host: {host}") from exc
    addresses = sorted({str(answer[4][0]) for answer in answers})
    if not addresses:
        raise UnsafeNetworkTarget(f"connection host resolved to no addresses: {host}")
    blocked = [address for address in addresses if is_ip_blocked(address, allow_private_ips)]
    if blocked:
        # Reject the whole answer, rather than choosing a safe member from a rebinding/mixed set.
        raise UnsafeNetworkTarget(f"connection host resolved to a blocked address: {host}")
    return addresses


async def resolve_validated_addresses(
    host: str,
    port: int,
    allow_private_ips: bool,
    *,
    timeout: float | None,
    max_addresses: int = _MAX_RESOLVED_ADDRESSES,
    resolver: Callable[[str, int, bool], list[str]] | None = None,
) -> list[str]:
    """Resolve under a bounded worker budget and retain that slot until the worker exits."""
    loop = asyncio.get_running_loop()
    semaphore = _RESOLVER_SEMAPHORES.get(loop)
    if semaphore is None:
        semaphore = asyncio.Semaphore(_MAX_RESOLVER_WORKERS)
        _RESOLVER_SEMAPHORES[loop] = semaphore
    deadline = None if timeout is None else loop.time() + max(0.0, timeout)

    async def remaining() -> float | None:
        if deadline is None:
            return None
        value = deadline - loop.time()
        if value <= 0:
            raise TimeoutError(f"DNS resolution timed out for {host}")
        return value

    acquire_timeout = await remaining()
    if acquire_timeout is None:
        await semaphore.acquire()
    else:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=acquire_timeout)
        except asyncio.TimeoutError as exc:
            # Python 3.10 exposes asyncio.TimeoutError separately from builtins.TimeoutError.
            # Normalize the public contract so PinnedNetworkBackend maps every DNS timeout.
            raise TimeoutError(f"DNS resolution timed out for {host}") from exc

    resolver_impl = resolver or _resolve_validated_addresses
    worker = asyncio.create_task(
        asyncio.to_thread(resolver_impl, host, port, allow_private_ips)
    )

    def release_worker_slot(task: asyncio.Task[list[str]]) -> None:
        semaphore.release()
        if not task.cancelled():
            with suppress(BaseException):
                task.exception()

    worker.add_done_callback(release_worker_slot)
    try:
        worker_timeout = await remaining()
        if worker_timeout is None:
            addresses = await asyncio.shield(worker)
        else:
            addresses = await asyncio.wait_for(asyncio.shield(worker), timeout=worker_timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(f"DNS resolution timed out for {host}") from exc
    except asyncio.CancelledError:
        # ``to_thread`` cannot be cancelled safely. Shielding lets the worker finish while its
        # semaphore slot remains held, preventing timed-out DNS work from growing without bound.
        raise
    return addresses[: max(1, max_addresses)]


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve and validate immediately before dialing the exact validated IP address.

    httpcore still owns TLS and passes the original origin hostname as SNI, so certificate and Host
    validation remain correct while the TCP destination cannot change between policy check and use.
    """

    def __init__(self, *, allow_private_ips: bool = False, backend: Any | None = None):
        self.allow_private_ips = allow_private_ips
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + max(0.0, timeout)
        try:
            addresses = await resolve_validated_addresses(
                host,
                port,
                self.allow_private_ips,
                timeout=timeout,
            )
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"connection timed out resolving {host}") from exc
        last_error: BaseException | None = None
        for address in addresses:
            try:
                remaining_timeout = (
                    None if deadline is None else max(0.0, deadline - loop.time())
                )
                if remaining_timeout == 0:
                    raise httpcore.ConnectTimeout(f"connection timed out for {host}")
                return await self._backend.connect_tcp(
                    host=address,
                    port=port,
                    timeout=remaining_timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except BaseException as exc:
                if isinstance(exc, asyncio.CancelledError):
                    raise
                last_error = exc
        if last_error is not None:
            if isinstance(last_error, TimeoutError):
                raise httpcore.ConnectTimeout(f"connection timed out for {host}") from last_error
            raise last_error
        raise UnsafeNetworkTarget(f"no validated address could be connected: {host}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # The BundleInspector HTTP client never enables UDS. Fail closed if a future caller does.
        raise UnsafeNetworkTarget("unix-domain sockets are disabled for remote scanning")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def build_pinned_transport(
    *,
    allow_private_ips: bool,
    max_connections: int,
) -> httpx.AsyncHTTPTransport:
    """Create an HTTPX transport whose connection pool uses ``PinnedNetworkBackend``."""
    limits = httpx.Limits(
        max_connections=max(1, max_connections),
        max_keepalive_connections=max(1, max_connections),
    )
    transport = httpx.AsyncHTTPTransport(
        trust_env=False,
        retries=0,
        limits=limits,
    )
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("installed httpx/httpcore does not expose a pinnable network backend")
    pool._network_backend = PinnedNetworkBackend(
        allow_private_ips=allow_private_ips
    )
    return transport
