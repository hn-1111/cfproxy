"""The bridge end to end: app -> bridge -> tunnel -> the real Worker code -> echo server / fake Telegram."""
import asyncio
import os
import socket
import struct
import unittest

import helpers
from helpers import HOST, NEED_EDGE, SECRET_HEX, fixtures, settings

import cfp_mtproto as mt
from cfp_bridge import Bridge, clean_host, socks_code_for, socks_reply
from cfp_tunnel import Endpoint, EndpointPool, TunnelError, TunnelRefused


async def socks_open(port, host, target_port, user=None, password=None, atyp=None):
    """A minimal SOCKS5 client. Returns (reader, writer, reply code); code -1 = refused during the greeting."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(bytes([5, 1, 2 if user is not None else 0]))
    method = await reader.readexactly(2)
    if method[1] == 0xFF:
        return reader, writer, -1
    if method[1] == 2:
        u, p = user.encode(), password.encode()
        writer.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        if (await reader.readexactly(2))[1] != 0:
            return reader, writer, -2
    try:
        socket.inet_aton(host)
        address = b"\x01" + socket.inet_aton(host) if atyp is None else b"\x03" + bytes([len(host)]) + host.encode()
    except OSError:
        address = b"\x03" + bytes([len(host)]) + host.encode()
    writer.write(b"\x05\x01\x00" + address + struct.pack(">H", target_port))
    head = await reader.readexactly(10)
    return reader, writer, head[1]


def make_bridge(st, endpoints, plain_ok=True, **kw):
    tls_only = [e for e in endpoints if e.tls]
    return Bridge(st, EndpointPool(tls_only or endpoints), EndpointPool(endpoints), **kw)


@unittest.skipUnless(NEED_EDGE, "needs node and openssl")
class SocksThroughTheWorker(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()

    async def asyncSetUp(self):
        self.plain = Endpoint("127.0.0.1", self.fx.edge.plain, tls=False)
        self.tls = Endpoint("127.0.0.1", self.fx.edge.tls, tls=True)

    async def start(self, **settings_kw):
        st = settings(ssl_context=self.fx.tls_context, **settings_kw)
        bridge = make_bridge(st, [self.tls, self.plain])
        await bridge.start()
        self.addAsyncCleanup(bridge.close)
        return bridge

    async def test_a_connection_is_carried_both_ways(self):
        bridge = await self.start()
        reader, writer, code = await socks_open(bridge.socks_port, "127.0.0.1", self.fx.echo.port)
        self.assertEqual(code, 0)
        payload = os.urandom(300_000)  # bigger than one WebSocket message and than the socket buffers
        writer.write(payload)
        got = await asyncio.wait_for(reader.readexactly(len(payload)), 20)
        self.assertEqual(got, payload)
        writer.close()
        self.assertEqual(bridge.stats.socks, 1)

    async def test_domain_names_are_resolved_by_the_worker(self):
        bridge = await self.start()
        reader, writer, code = await socks_open(bridge.socks_port, "localhost", self.fx.echo.port)
        self.assertEqual(code, 0)
        writer.write(b"hello")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 10), b"hello")
        writer.close()

    async def test_username_and_password(self):
        bridge = await self.start(socks_user="alice", socks_pass="s3cret")
        _, w, code = await socks_open(bridge.socks_port, "127.0.0.1", self.fx.echo.port)
        self.assertEqual(code, -1)  # no credentials offered: refused
        w.close()
        _, w, code = await socks_open(bridge.socks_port, "127.0.0.1", self.fx.echo.port, "alice", "wrong")
        self.assertEqual(code, -2)
        w.close()
        reader, w, code = await socks_open(bridge.socks_port, "127.0.0.1", self.fx.echo.port, "alice", "s3cret")
        self.assertEqual(code, 0)
        w.write(b"ok")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 10), b"ok")
        w.close()

    async def test_a_closed_port_is_reported_as_refused(self):
        bridge = await self.start()
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        _, w, code = await socks_open(bridge.socks_port, "127.0.0.1", dead)
        self.assertEqual(code, 5)
        w.close()

    async def test_other_commands_are_not_supported(self):
        bridge = await self.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", bridge.socks_port)
        writer.write(b"\x05\x01\x00")
        await reader.readexactly(2)
        writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # UDP ASSOCIATE
        self.assertEqual((await reader.readexactly(10))[1], 7)
        writer.close()

    async def test_socks_uses_the_tls_endpoint_only(self):
        bridge = await self.start()
        self.assertEqual([e.tls for e in bridge.socks_pool.endpoints], [True])
        self.assertEqual(len(bridge.mtproto_pool.endpoints), 2)

    async def test_a_dead_endpoint_is_skipped(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = Endpoint("127.0.0.1", probe.getsockname()[1], tls=False)
        probe.close()
        st = settings(ssl_context=self.fx.tls_context)
        bridge = Bridge(st, EndpointPool([dead, self.tls]), None)
        await bridge.start()
        self.addAsyncCleanup(bridge.close)
        reader, writer, code = await socks_open(bridge.socks_port, "127.0.0.1", self.fx.echo.port)
        self.assertEqual(code, 0)
        writer.write(b"x")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 10), b"x")
        writer.close()
        self.assertIn(dead, bridge.socks_pool._bad_until)

    async def test_the_worker_cannot_be_reached_at_all(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = Endpoint("127.0.0.1", probe.getsockname()[1], tls=False)
        probe.close()
        bridge = Bridge(settings(), EndpointPool([dead]), None)
        await bridge.start()
        self.addAsyncCleanup(bridge.close)
        _, w, code = await socks_open(bridge.socks_port, "127.0.0.1", 9)
        self.assertEqual(code, 3)  # network unreachable
        w.close()


@unittest.skipUnless(NEED_EDGE, "needs node and openssl")
class MtprotoThroughTheWorker(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()

    async def asyncSetUp(self):
        self.tls = Endpoint("127.0.0.1", self.fx.edge.tls, tls=True)
        st = settings(ssl_context=self.fx.tls_context)
        self.bridge = Bridge(st, None, EndpointPool([self.tls]))
        await self.bridge.start()
        self.addAsyncCleanup(self.bridge.close)

    async def connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.bridge.mtproto_port)
        self.addCleanup(writer.close)
        return reader, writer

    async def test_telegram_answers_through_the_bridge(self):
        reader, writer = await self.connect()

        async def send(data):
            writer.write(data)
            await writer.drain()

        async def recv():
            data = await reader.read(65536)
            return data or None

        before = len(self.fx.telegram.seen)
        result = await mt.probe_telegram(send, recv, dc=2, secret=bytes.fromhex(SECRET_HEX), timeout=10)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.fx.telegram.seen[before][1], 2)  # the bridge asked data centre 2 for the app
        self.assertEqual(self.bridge.stats.mtproto, 1)

    async def test_the_media_data_centre_number_is_passed_on(self):
        reader, writer = await self.connect()
        handshake, enc, dec = mt.client_handshake(mt.PROTO_PADDED, -2, bytes.fromhex(SECRET_HEX))
        before = len(self.fx.telegram.seen)
        writer.write(handshake + enc.process(mt.req_pq_frame(os.urandom(16))))
        await asyncio.wait_for(reader.read(65536), 10)
        proto, dc = self.fx.telegram.seen[before]
        self.assertEqual((proto, dc), (mt.PROTO_PADDED, -2))

    async def test_a_large_stream_survives_the_two_encryptions(self):
        reader, writer = await self.connect()
        handshake, enc, dec = mt.client_handshake(mt.PROTO_INTERMEDIATE, 4, bytes.fromhex(SECRET_HEX))
        writer.write(handshake + enc.process(mt.req_pq_frame(os.urandom(16))))
        first = dec.process(await asyncio.wait_for(reader.read(65536), 10))
        self.assertEqual(first[0] * 4 + 1, len(first))  # the resPQ frame (abridged framing is irrelevant here)
        payload = os.urandom(250_000)
        writer.write(enc.process(payload))
        got = b""
        while len(got) < len(payload):
            chunk = await asyncio.wait_for(reader.read(65536), 20)
            self.assertTrue(chunk)
            got += dec.process(chunk)
        self.assertEqual(got, payload)

    async def test_the_wrong_secret_gets_nothing(self):
        reader, writer = await self.connect()
        handshake, enc, dec = mt.client_handshake(mt.PROTO_ABRIDGED, 2, bytes(range(16)))
        writer.write(handshake + enc.process(mt.req_pq_frame(os.urandom(16))))
        data = await asyncio.wait_for(reader.read(65536), 10)
        self.assertEqual(data, b"")  # closed without a word
        self.assertEqual(self.bridge.stats.mtproto, 0)


class SmallPieces(unittest.TestCase):
    def test_socks_reply_layout(self):
        self.assertEqual(socks_reply(5), b"\x05\x05\x00\x01" + bytes(6))

    def test_error_codes(self):
        self.assertEqual(socks_code_for(TunnelRefused("x", "connect")), 5)
        self.assertEqual(socks_code_for(TunnelRefused("x", "forbidden")), 2)
        self.assertEqual(socks_code_for(TunnelRefused("x", "auth")), 1)
        self.assertEqual(socks_code_for(TunnelError("x")), 3)

    def test_clean_host(self):
        self.assertEqual(clean_host(b"example.com"), "example.com")
        self.assertEqual(clean_host("bücher.example".encode()), "xn--bcher-kva.example")


if __name__ == "__main__":
    unittest.main()
