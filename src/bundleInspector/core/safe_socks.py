"""A loopback SOCKS5 proxy that binds DNS policy checks to the socket dial."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from contextlib import suppress
from types import TracebackType

from bundleInspector.core.safe_http import (
    UnsafeNetworkTarget,
    _resolve_validated_addresses,
    resolve_validated_addresses,
)

logger = logging.getLogger(__name__)

_SOCKS_VERSION = 5
_NO_AUTH = 0
_CONNECT = 1
_IPV4 = 1
_DOMAIN = 3
_IPV6 = 4
_REPLY_GENERAL_FAILURE = 1
_REPLY_NOT_ALLOWED = 2
_REPLY_HOST_UNREACHABLE = 4
_REPLY_COMMAND_UNSUPPORTED = 7
_REPLY_ADDRESS_UNSUPPORTED = 8
_RELAY_CHUNK_SIZE = 64 * 1024
_MAX_DOMAIN_BYTES = 253
_DEFAULT_MAX_CLIENTS = 256
_CLOSE_TIMEOUT = 1.0


class _SocksProtocolError(Exception):
    """A malformed or unsupported SOCKS request with an associated reply code."""

    def __init__(self, reply_code: int, message: str, *, replied: bool = False):
        super().__init__(message)
        self.reply_code = reply_code
        self.replied = replied


async def _open_connection_to_address(
    address: str,
    port: int,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Dial a numeric address without allowing another hostname resolution."""
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    raw_socket = socket.socket(family, socket.SOCK_STREAM)
    raw_socket.setblocking(False)
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().sock_connect(raw_socket, (str(ip), port)),
            timeout=timeout,
        )
        return await asyncio.open_connection(sock=raw_socket)
    except BaseException:
        raw_socket.close()
        raise


class ValidatingSocksProxy:
    """SOCKS5 CONNECT proxy whose resolver result is the address actually dialed.

    The browser retains the original hostname inside its TLS tunnel, so certificate validation and
    SNI stay end-to-end while DNS rebinding cannot swap the TCP destination after validation.
    """

    def __init__(
        self,
        *,
        allow_private_ips: bool = False,
        connect_timeout: float = 30.0,
        handshake_timeout: float = 10.0,
        max_clients: int = _DEFAULT_MAX_CLIENTS,
    ) -> None:
        self.allow_private_ips = allow_private_ips
        self.connect_timeout = max(0.1, float(connect_timeout))
        self.handshake_timeout = max(0.1, float(handshake_timeout))
        self.max_clients = max(1, int(max_clients))
        self._server: asyncio.AbstractServer | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._closing = False
        self._port: int | None = None

    @property
    def port(self) -> int:
        """Return the bound loopback port after ``start``."""
        if self._port is None:
            raise RuntimeError("SOCKS proxy is not running")
        return self._port

    @property
    def url(self) -> str:
        """Return the Playwright-compatible proxy URL."""
        return f"socks5://127.0.0.1:{self.port}"

    async def start(self) -> None:
        """Start the loopback-only listener; repeated calls are idempotent."""
        if self._server is not None:
            return
        self._closing = False
        server = await asyncio.start_server(
            self._accept_client,
            host="127.0.0.1",
            port=0,
            limit=_RELAY_CHUNK_SIZE,
        )
        if not server.sockets:
            server.close()
            await server.wait_closed()
            raise RuntimeError("SOCKS proxy did not expose a listening socket")
        self._server = server
        self._port = int(server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        """Stop accepting clients and cancel/await every owned connection task."""
        self._closing = True
        server = self._server
        self._server = None
        self._port = None
        if server is not None:
            server.close()

        tasks = list(self._client_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._client_tasks.clear()
        if server is not None:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=_CLOSE_TIMEOUT)
            except TimeoutError:
                logger.debug("Timed out waiting for SOCKS listener shutdown")

    async def __aenter__(self) -> ValidatingSocksProxy:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    def _accept_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self._closing or len(self._client_tasks) >= self.max_clients:
            writer.close()
            return
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._on_client_done)

    def _on_client_done(self, task: asyncio.Task[None]) -> None:
        self._client_tasks.discard(task)
        if task.cancelled():
            return
        try:
            error = task.exception()
        except asyncio.CancelledError:
            return
        if error is not None:
            logger.debug("SOCKS client task failed", exc_info=error)

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            target = await asyncio.wait_for(
                self._read_target(client_reader, client_writer),
                timeout=self.handshake_timeout,
            )
            if target is None:
                return
            host, port = target
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.connect_timeout
            addresses = await resolve_validated_addresses(
                host,
                port,
                self.allow_private_ips,
                timeout=self.connect_timeout,
                resolver=_resolve_validated_addresses,
            )
            upstream_reader, upstream_writer = await self._connect_upstream(
                addresses,
                port,
                deadline=deadline,
            )
            await self._send_reply(client_writer, 0, upstream_writer)
            await self._relay_bidirectionally(
                client_reader,
                client_writer,
                upstream_reader,
                upstream_writer,
            )
        except asyncio.CancelledError:
            raise
        except UnsafeNetworkTarget:
            await self._send_failure(client_writer, _REPLY_NOT_ALLOWED)
        except _SocksProtocolError as exc:
            if not exc.replied:
                await self._send_failure(client_writer, exc.reply_code)
        except (TimeoutError, OSError):
            await self._send_failure(client_writer, _REPLY_HOST_UNREACHABLE)
        except Exception:
            logger.debug("Unexpected SOCKS proxy failure", exc_info=True)
            await self._send_failure(client_writer, _REPLY_GENERAL_FAILURE)
        finally:
            writers = (
                (upstream_writer, client_writer)
                if upstream_writer is not None
                else (client_writer,)
            )
            await self._close_writers(*writers)

    async def _read_target(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> tuple[str, int] | None:
        version, method_count = await self._read_exact(reader, 2)
        if version != _SOCKS_VERSION or method_count == 0:
            raise _SocksProtocolError(_REPLY_GENERAL_FAILURE, "invalid SOCKS greeting")
        methods = await self._read_exact(reader, method_count)
        if _NO_AUTH not in methods:
            writer.write(bytes((_SOCKS_VERSION, 0xFF)))
            await writer.drain()
            return None
        writer.write(bytes((_SOCKS_VERSION, _NO_AUTH)))
        await writer.drain()

        version, command, reserved, address_type = await self._read_exact(reader, 4)
        if version != _SOCKS_VERSION or reserved != 0:
            raise _SocksProtocolError(_REPLY_GENERAL_FAILURE, "invalid SOCKS request header")
        if command != _CONNECT:
            raise _SocksProtocolError(
                _REPLY_COMMAND_UNSUPPORTED,
                "only SOCKS CONNECT is supported",
            )

        if address_type == _IPV4:
            host = socket.inet_ntop(socket.AF_INET, await self._read_exact(reader, 4))
        elif address_type == _IPV6:
            host = socket.inet_ntop(socket.AF_INET6, await self._read_exact(reader, 16))
        elif address_type == _DOMAIN:
            domain_length = (await self._read_exact(reader, 1))[0]
            if domain_length == 0 or domain_length > _MAX_DOMAIN_BYTES:
                raise _SocksProtocolError(_REPLY_ADDRESS_UNSUPPORTED, "invalid SOCKS domain")
            domain_bytes = await self._read_exact(reader, domain_length)
            try:
                host = domain_bytes.decode("ascii")
                host.encode("idna")
            except (UnicodeError, UnicodeDecodeError) as exc:
                raise _SocksProtocolError(
                    _REPLY_ADDRESS_UNSUPPORTED,
                    "invalid SOCKS domain encoding",
                ) from exc
        else:
            raise _SocksProtocolError(
                _REPLY_ADDRESS_UNSUPPORTED,
                "unsupported SOCKS address type",
            )

        port = int.from_bytes(await self._read_exact(reader, 2), "big")
        if port == 0:
            raise _SocksProtocolError(_REPLY_ADDRESS_UNSUPPORTED, "invalid SOCKS port")
        return host, port

    async def _connect_upstream(
        self,
        addresses: list[str],
        port: int,
        *,
        deadline: float,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        last_error: BaseException | None = None
        loop = asyncio.get_running_loop()
        for address in addresses:
            try:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise TimeoutError("SOCKS connection deadline expired")
                return await _open_connection_to_address(
                    address,
                    port,
                    remaining,
                )
            except asyncio.CancelledError:
                raise
            except (TimeoutError, OSError, ValueError) as exc:
                last_error = exc
        if last_error is not None:
            raise OSError("all validated SOCKS destinations failed") from last_error
        raise OSError("SOCKS destination resolved to no validated addresses")

    @staticmethod
    async def _read_exact(reader: asyncio.StreamReader, size: int) -> bytes:
        try:
            return await reader.readexactly(size)
        except asyncio.IncompleteReadError as exc:
            raise _SocksProtocolError(
                _REPLY_GENERAL_FAILURE,
                "truncated SOCKS request",
            ) from exc

    @staticmethod
    async def _send_reply(
        writer: asyncio.StreamWriter,
        reply_code: int,
        upstream_writer: asyncio.StreamWriter | None = None,
    ) -> None:
        address = ipaddress.ip_address("0.0.0.0")
        port = 0
        if upstream_writer is not None:
            sockname = upstream_writer.get_extra_info("sockname")
            if isinstance(sockname, tuple) and len(sockname) >= 2:
                try:
                    address = ipaddress.ip_address(str(sockname[0]))
                    port = int(sockname[1])
                except (TypeError, ValueError):
                    address = ipaddress.ip_address("0.0.0.0")
                    port = 0
        address_type = _IPV6 if address.version == 6 else _IPV4
        writer.write(
            bytes((_SOCKS_VERSION, reply_code, 0, address_type))
            + address.packed
            + port.to_bytes(2, "big")
        )
        await writer.drain()

    @classmethod
    async def _send_failure(cls, writer: asyncio.StreamWriter, reply_code: int) -> None:
        if writer.is_closing():
            return
        with suppress(ConnectionError, OSError):
            await cls._send_reply(writer, reply_code)

    @staticmethod
    async def _pipe(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        while True:
            chunk = await reader.read(_RELAY_CHUNK_SIZE)
            if not chunk:
                if writer.can_write_eof():
                    with suppress(ConnectionError, OSError):
                        writer.write_eof()
                        await writer.drain()
                return
            writer.write(chunk)
            await writer.drain()

    @classmethod
    async def _relay_bidirectionally(
        cls,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        tasks = {
            asyncio.create_task(cls._pipe(client_reader, upstream_writer)),
            asyncio.create_task(cls._pipe(upstream_reader, client_writer)),
        }
        try:
            while tasks:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    error = task.exception()
                    if error is not None:
                        raise error
                tasks = pending
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    @classmethod
    async def _close_writers(cls, *writers: asyncio.StreamWriter) -> None:
        # Close every transport before the first await. Proxy shutdown can cancel this task while
        # one wait_closed() is pending; later writers must not be left open in that race.
        for writer in writers:
            with suppress(ConnectionError, OSError, RuntimeError):
                writer.close()
        try:
            for writer in writers:
                await cls._wait_writer_closed(writer)
        except asyncio.CancelledError:
            for writer in writers:
                with suppress(ConnectionError, OSError, RuntimeError):
                    writer.transport.abort()
            raise

    @staticmethod
    async def _wait_writer_closed(writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=_CLOSE_TIMEOUT)
        except TimeoutError:
            with suppress(ConnectionError, OSError, RuntimeError):
                writer.transport.abort()
        except (ConnectionError, OSError, RuntimeError):
            return
