"""Protocol and lifecycle tests for the DNS-pinning SOCKS5 proxy."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import pytest

from bundleInspector.core import safe_socks
from bundleInspector.core.safe_http import UnsafeNetworkTarget
from bundleInspector.core.safe_socks import ValidatingSocksProxy


async def _read_socks_reply(reader: asyncio.StreamReader) -> tuple[int, int]:
    version, reply_code, reserved, address_type = await reader.readexactly(4)
    assert version == 5
    assert reserved == 0
    if address_type == 1:
        await reader.readexactly(4)
    elif address_type == 4:
        await reader.readexactly(16)
    elif address_type == 3:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length)
    else:
        raise AssertionError(f"unexpected SOCKS address type: {address_type}")
    port = int.from_bytes(await reader.readexactly(2), "big")
    return reply_code, port


async def _connect_through_proxy(
    proxy: ValidatingSocksProxy,
    host: str,
    port: int,
    *,
    command: int = 1,
    address_type: int = 3,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int]:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    if address_type == 3:
        encoded = host.encode("ascii")
        address = bytes((len(encoded),)) + encoded
    elif address_type == 1:
        address = bytes(int(part) for part in host.split("."))
    else:
        address = b""
    writer.write(bytes((5, command, 0, address_type)) + address + port.to_bytes(2, "big"))
    await writer.drain()
    reply_code, _ = await _read_socks_reply(reader)
    return reader, writer, reply_code


async def _start_server(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
) -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    assert server.sockets
    return server, int(server.sockets[0].getsockname()[1])


@pytest.mark.asyncio
async def test_proxy_dials_the_exact_validated_address_and_relays(monkeypatch) -> None:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.readexactly(4)
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    upstream, upstream_port = await _start_server(echo)
    resolver_calls: list[tuple[str, int, bool]] = []
    dial_calls: list[tuple[str, int, float]] = []
    real_dial = safe_socks._open_connection_to_address

    def resolve(host: str, port: int, allow_private_ips: bool) -> list[str]:
        resolver_calls.append((host, port, allow_private_ips))
        return ["127.0.0.1"]

    async def dial(
        address: str,
        port: int,
        timeout: float,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        dial_calls.append((address, port, timeout))
        return await real_dial(address, port, timeout)

    monkeypatch.setattr(safe_socks, "_resolve_validated_addresses", resolve)
    monkeypatch.setattr(safe_socks, "_open_connection_to_address", dial)
    proxy = ValidatingSocksProxy(allow_private_ips=False, connect_timeout=2)
    await proxy.start()
    client_writer: asyncio.StreamWriter | None = None
    try:
        client_reader, client_writer, reply = await _connect_through_proxy(
            proxy,
            "public.example",
            upstream_port,
        )
        assert reply == 0
        client_writer.write(b"ping")
        await client_writer.drain()
        assert await asyncio.wait_for(client_reader.readexactly(4), timeout=2) == b"ping"
        assert resolver_calls == [("public.example", upstream_port, False)]
        assert len(dial_calls) == 1
        assert dial_calls[0][:2] == ("127.0.0.1", upstream_port)
        assert 0 < dial_calls[0][2] <= 2.0
    finally:
        if client_writer is not None:
            client_writer.close()
            await client_writer.wait_closed()
        await proxy.close()
        upstream.close()
        await upstream.wait_closed()


@pytest.mark.asyncio
async def test_proxy_rejects_blocked_or_mixed_dns_without_dialing(monkeypatch) -> None:
    seen: list[tuple[str, int, bool]] = []

    def reject(host: str, port: int, allow_private_ips: bool) -> list[str]:
        seen.append((host, port, allow_private_ips))
        raise UnsafeNetworkTarget("mixed public/private DNS answer")

    async def forbidden_dial(*args, **kwargs):
        raise AssertionError("blocked DNS answer must never reach the dialer")

    monkeypatch.setattr(safe_socks, "_resolve_validated_addresses", reject)
    monkeypatch.setattr(safe_socks, "_open_connection_to_address", forbidden_dial)
    async with ValidatingSocksProxy(allow_private_ips=True) as proxy:
        reader, writer, reply = await _connect_through_proxy(proxy, "rebind.example", 443)
        try:
            assert reply == 2
            assert seen == [("rebind.example", 443, True)]
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "address_type", "expected_reply"),
    [
        (2, 3, 7),
        (3, 3, 7),
        (1, 9, 8),
    ],
)
async def test_proxy_rejects_unsupported_commands_and_address_types(
    command: int,
    address_type: int,
    expected_reply: int,
) -> None:
    async with ValidatingSocksProxy() as proxy:
        _, writer, reply = await _connect_through_proxy(
            proxy,
            "example.com",
            443,
            command=command,
            address_type=address_type,
        )
        try:
            assert reply == expected_reply
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_proxy_rejects_clients_without_no_auth_method() -> None:
    async with ValidatingSocksProxy() as proxy:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\xff"
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_proxy_preserves_reverse_relay_after_client_half_close(monkeypatch) -> None:
    async def reply_after_eof(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            assert await reader.read() == b"request"
            writer.write(b"response")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    upstream, upstream_port = await _start_server(reply_after_eof)
    monkeypatch.setattr(
        safe_socks,
        "_resolve_validated_addresses",
        lambda host, port, allow_private_ips: ["127.0.0.1"],
    )
    proxy = ValidatingSocksProxy(connect_timeout=2)
    await proxy.start()
    client_writer: asyncio.StreamWriter | None = None
    try:
        client_reader, client_writer, reply = await _connect_through_proxy(
            proxy,
            "half-close.example",
            upstream_port,
        )
        assert reply == 0
        client_writer.write(b"request")
        await client_writer.drain()
        assert client_writer.can_write_eof()
        client_writer.write_eof()
        assert await asyncio.wait_for(client_reader.readexactly(8), timeout=2) == b"response"
    finally:
        if client_writer is not None:
            client_writer.close()
            await client_writer.wait_closed()
        await proxy.close()
        upstream.close()
        await upstream.wait_closed()


@pytest.mark.asyncio
async def test_proxy_close_cancels_and_awaits_incomplete_clients() -> None:
    proxy = ValidatingSocksProxy(handshake_timeout=30)
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    try:
        for _ in range(20):
            if proxy._client_tasks:
                break
            await asyncio.sleep(0)
        assert proxy._client_tasks
        await asyncio.wait_for(proxy.close(), timeout=2)
        assert proxy._client_tasks == set()
        assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        await proxy.close()
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_client_cancellation_closes_both_sides_before_waiting(monkeypatch) -> None:
    class _Transport:
        def __init__(self) -> None:
            self.aborted = False

        def abort(self) -> None:
            self.aborted = True

    class _Writer:
        def __init__(self, *, block_wait: bool) -> None:
            self.closed = False
            self.close_started = asyncio.Event()
            self.transport = _Transport()
            self._block_wait = block_wait

        def close(self) -> None:
            self.closed = True
            self.close_started.set()

        async def wait_closed(self) -> None:
            if self._block_wait:
                await asyncio.Event().wait()

    upstream_writer = _Writer(block_wait=True)
    client_writer = _Writer(block_wait=False)
    proxy = ValidatingSocksProxy()

    async def read_target(*args, **kwargs):
        return "public.example", 443

    async def connect_upstream(*args, **kwargs):
        return object(), upstream_writer

    async def no_op(*args, **kwargs):
        return None

    monkeypatch.setattr(safe_socks, "_resolve_validated_addresses", lambda *args: ["203.0.113.1"])
    monkeypatch.setattr(proxy, "_read_target", read_target)
    monkeypatch.setattr(proxy, "_connect_upstream", connect_upstream)
    monkeypatch.setattr(proxy, "_send_reply", no_op)
    monkeypatch.setattr(proxy, "_relay_bidirectionally", no_op)

    task = asyncio.create_task(proxy._handle_client(object(), client_writer))
    await asyncio.wait_for(upstream_writer.close_started.wait(), timeout=1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert upstream_writer.closed is True
    assert client_writer.closed is True
