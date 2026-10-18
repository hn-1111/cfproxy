"""The local half of cfproxy: a SOCKS5 server and an MTProto proxy server that carry every connection through a
tunnel to the Worker (cfp_tunnel.py), over clean Cloudflare IPs.

  app --SOCKS5 / MTProto--> this bridge --WebSocket (TLS or plain)--> Cloudflare --> Worker --TCP--> the target

The bridge never looks inside the traffic. For MTProto it only re-encrypts the byte stream: the app's obfuscated2
session (keyed with your secret) is opened here and a fresh obfuscated2 session is started towards Telegram's data
centre, so the Worker only ever carries what Telegram itself would see.

Standard library only (AES comes from cfp_mtproto).
"""
from __future__ import annotations

import asyncio
import hmac
import socket
import struct
from dataclasses import dataclass

import cfp_mtproto as mt
from cfp_common import TG_DCS, TG_PORT, Settings, dim, info, warn
from cfp_tunnel import EndpointPool, Tunnel, TunnelError, TunnelRefused, open_tunnel

HANDSHAKE_TIMEOUT = 15.0   # seconds an app may take to say what it wants
RELAY_GRACE = 3.0          # after the app stops sending, how long the answer may still arrive
CHUNK = 64 * 1024

# SOCKS5 reply codes (RFC 1928)
REP_OK, REP_FAIL, REP_DENIED, REP_NET, REP_HOST, REP_REFUSED = 0, 1, 2, 3, 4, 5
REP_CMD, REP_ATYP = 7, 8


@dataclass
class Stats:
    socks: int = 0
    mtproto: int = 0
    active: int = 0
    failed: int = 0
    up: int = 0
    down: int = 0


def socks_reply(code: int) -> bytes:
    return bytes([5, code, 0, 1]) + bytes(4) + bytes(2)


def socks_code_for(error: Exception) -> int:
    """What an app is told when the tunnel could not be opened."""
    if isinstance(error, TunnelRefused):
        return {"connect": REP_REFUSED, "forbidden": REP_DENIED}.get(error.code, REP_FAIL)
    return REP_NET  # the Worker itself could not be reached through any endpoint


def clean_host(raw: bytes) -> str:
    """A SOCKS5 domain name as the Worker wants it: ASCII (internationalised names become punycode)."""
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.decode("utf-8").encode("idna").decode("ascii")


async def close_writer(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    except Exception:  # the peer is gone already
        pass


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tunnel: Tunnel, up=None, down=None,
                stats: Stats | None = None) -> None:
    """Copies bytes between the app's socket and the tunnel until either side ends. `up` / `down` transform the
    bytes that travel towards the tunnel / towards the app (MTProto re-encryption)."""

    async def app_to_tunnel():
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    return
                if up:
                    data = up(data)
                if stats:
                    stats.up += len(data)
                await tunnel.send(data)
        except (OSError, TunnelError):
            return

    async def tunnel_to_app():
        try:
            while True:
                data = await tunnel.recv()
                if data is None:
                    return
                if down:
                    data = down(data)
                if stats:
                    stats.down += len(data)
                writer.write(data)
                await writer.drain()
        except OSError:
            return

    sender = asyncio.ensure_future(app_to_tunnel())
    receiver = asyncio.ensure_future(tunnel_to_app())
    try:
        done, _ = await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
        if receiver not in done:
            # the app stopped sending (maybe it only half-closed): let the answer arrive for a moment
            await asyncio.wait({receiver}, timeout=RELAY_GRACE)
    finally:
        for task in (sender, receiver):
            task.cancel()
        await asyncio.gather(sender, receiver, return_exceptions=True)
        await tunnel.close()
        await close_writer(writer)


class Bridge:
    """SOCKS5 on one port, MTProto on another, both through the Worker.

    socks_pool / mtproto_pool: the Cloudflare endpoints each service may use (see EndpointPool). SOCKS5 carries your
    traffic in the clear inside the tunnel, so by default it only gets the TLS endpoints; MTProto is encrypted by
    Telegram itself and may use every endpoint, plain HTTP ports included."""

    def __init__(self, st: Settings, socks_pool: EndpointPool | None, mtproto_pool: EndpointPool | None,
                 listen: str = "127.0.0.1", verbose: bool = False, max_connections: int = 512):
        self.st = st
        self.socks_pool = socks_pool
        self.mtproto_pool = mtproto_pool
        self.listen = listen
        self.verbose = verbose
        self.stats = Stats()
        self._servers: list = []
        self._tasks: set = set()
        self._limit = asyncio.Semaphore(max_connections)
        self.socks_port = 0
        self.mtproto_port = 0
        self._secret = bytes.fromhex(st.mtproto_secret) if st.mtproto_secret else b""

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        if self.socks_pool is not None:
            server = await asyncio.start_server(self._guard(self.handle_socks), self.listen, self.st.socks_port)
            self._servers.append(server)
            self.socks_port = server.sockets[0].getsockname()[1]
        if self.mtproto_pool is not None:
            if not self._secret:
                raise ValueError("MTPROTO_SECRET is missing")
            server = await asyncio.start_server(self._guard(self.handle_mtproto), self.listen, self.st.mtproto_port)
            self._servers.append(server)
            self.mtproto_port = server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        for server in self._servers:
            server.close()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for server in self._servers:
            try:
                await asyncio.wait_for(server.wait_closed(), 2.0)
            except Exception:
                pass
        self._servers.clear()

    def _guard(self, handler):
        """Wraps a connection handler: limits concurrency, counts, logs, and never lets an error escape."""

        async def run(reader, writer):
            task = asyncio.current_task()
            self._tasks.add(task)
            peer = writer.get_extra_info("peername")
            try:
                async with self._limit:
                    self.stats.active += 1
                    try:
                        await handler(reader, writer)
                    finally:
                        self.stats.active -= 1
            except asyncio.CancelledError:
                pass
            except Exception as e:  # a broken client must never stop the server
                self.stats.failed += 1
                warn(f"{handler.__name__}: {peer}: {type(e).__name__}: {e}")
            finally:
                self._tasks.discard(task)
                await close_writer(writer)

        return run

    def note(self, text: str) -> None:
        if self.verbose:
            info(dim(text))

    # ------------------------------------------------------------ SOCKS5

    async def _socks_auth(self, reader, writer) -> bool:
        """Method negotiation and, when SOCKS_USER is set, the RFC 1929 username / password step."""
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5:
            return False
        if self.st.socks_user:
            if 2 not in methods:
                writer.write(b"\x05\xff")
                return False
            writer.write(b"\x05\x02")
            await writer.drain()
            await reader.readexactly(1)  # sub-negotiation version
            user = await reader.readexactly((await reader.readexactly(1))[0])
            password = await reader.readexactly((await reader.readexactly(1))[0])
            good = (hmac.compare_digest(user, self.st.socks_user.encode())
                    & hmac.compare_digest(password, self.st.socks_pass.encode()))
            writer.write(bytes([1, 0 if good else 1]))
            await writer.drain()
            return bool(good)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            return False
        writer.write(b"\x05\x00")
        await writer.drain()
        return True

    async def handle_socks(self, reader, writer) -> None:
        try:
            if not await asyncio.wait_for(self._socks_auth(reader, writer), HANDSHAKE_TIMEOUT):
                return
            version, command, _, atyp = await asyncio.wait_for(reader.readexactly(4), HANDSHAKE_TIMEOUT)
            if version != 5:
                return
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                host = clean_host(await reader.readexactly((await reader.readexactly(1))[0]))
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(socks_reply(REP_ATYP))
                return
            port = struct.unpack(">H", await reader.readexactly(2))[0]
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, UnicodeError, ConnectionError):
            return
        if command != 1:  # only CONNECT: BIND and UDP ASSOCIATE cannot travel through a WebSocket
            writer.write(socks_reply(REP_CMD))
            return
        self.stats.socks += 1
        try:
            tunnel = await open_tunnel(self.socks_pool, self.st, host, port)
        except TunnelError as e:
            self.note(f"socks {host}:{port} failed: {e}")
            writer.write(socks_reply(socks_code_for(e)))
            return
        self.note(f"socks {host}:{port} via {tunnel.endpoint}")
        writer.write(socks_reply(REP_OK))
        await writer.drain()
        await relay(reader, writer, tunnel, stats=self.stats)

    # ------------------------------------------------------------ MTProto

    async def _open_dc(self, dc: int) -> Tunnel:
        """A tunnel to Telegram's data centre `dc` (negative = its media servers, 10000+ = test servers)."""
        number = abs(dc)
        if number > 10000:
            number -= 10000
        options = TG_DCS.get(number) or TG_DCS[2]
        problem: Exception | None = None
        for ip in options:
            try:
                return await open_tunnel(self.mtproto_pool, self.st, ip, TG_PORT)
            except TunnelRefused as e:
                if e.code != "connect":
                    raise
                problem = e  # this address does not answer: the data centre may have another one
        raise problem or TunnelError("no data centre address")

    async def handle_mtproto(self, reader, writer) -> None:
        try:
            init = await asyncio.wait_for(reader.readexactly(64), HANDSHAKE_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            return
        opened = mt.server_handshake(init, [self._secret])
        if opened is None:
            self.stats.failed += 1
            self.note("mtproto: wrong secret (or not Telegram)")
            return
        proto, dc, app_in, app_out, _ = opened
        self.stats.mtproto += 1
        try:
            tunnel = await self._open_dc(dc)
        except TunnelError as e:
            self.note(f"mtproto dc{dc} failed: {e}")
            return
        hello, dc_out, dc_in = mt.client_handshake(proto, dc)
        try:
            await tunnel.send(hello)
        except TunnelError:
            await tunnel.close()
            return
        self.note(f"mtproto dc{dc} via {tunnel.endpoint}")
        await relay(reader, writer, tunnel,
                    up=lambda data: dc_out.process(app_in.process(data)),
                    down=lambda data: app_out.process(dc_in.process(data)),
                    stats=self.stats)
