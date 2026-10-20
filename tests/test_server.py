"""server/index.mjs, the tunnel exit that runs on Railway, started exactly as it is shipped (the Worker's code pasted into it)
and driven by the project's own client code: the tunnel protocol, the plain HTTP side, and what a Worker gets for free from
Cloudflare but a server must do itself (private addresses, silent connections, back-pressure)."""
import asyncio
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import helpers
from helpers import HAVE_NODE

import cfp_deploy as deploy
import fakes
from cfp_tunnel import make_hello
from cfp_ws import OP_BINARY, OP_CLOSE, OP_TEXT, WebSocket, WSError, encode_frame

TOKEN = "server-test-token-" + "k" * 20
PATH = "/s3rv3r-path"


class Exit:
    """The assembled app as a child process on a free local port."""

    def __init__(self, **env):
        self.folder = tempfile.mkdtemp(prefix="cfp-server-")
        self.file = os.path.join(self.folder, "app.mjs")
        with open(self.file, "w", encoding="utf-8") as f:
            f.write(deploy.railway_app(helpers.ROOT))
        self.port = fakes.free_port()
        settings = {"AUTH_TOKEN": TOKEN, "WS_PATH": PATH, "PORT": str(self.port), "HOST": "127.0.0.1"}
        settings.update(env)
        settings = {k: v for k, v in settings.items() if v is not None}
        self.proc = subprocess.Popen(["node", self.file], env={"PATH": os.environ["PATH"], **settings},
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.banner = self.proc.stdout.readline()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.proc.stdout.close()
        shutil.rmtree(self.folder, True)

    def get(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    async def open(self, path=PATH):
        return await WebSocket.open("127.0.0.1", self.port, "x.example", path, tls=False)


async def tunnel(exit_, host, port, token=TOKEN, ts=None):
    """An open WebSocket after its hello; returns (ws, the exit's first answer)."""
    ws = await exit_.open()
    await ws.send_text(make_hello(token, host, port, ts))
    _, payload = await asyncio.wait_for(ws.recv(), 10)
    return ws, json.loads(payload)


async def closed_within(ws, seconds=10):
    """True once the server has closed the connection (recv() gives None); any data that comes first is skipped."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if await asyncio.wait_for(ws.recv(), max(0.1, deadline - time.monotonic())) is None:
            return True
    return False


class Target:
    """A local TCP server: `behaviour(reader, writer)` is what the 'internet' does."""

    def __init__(self, behaviour):
        self.behaviour = behaviour

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.behaviour, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


async def shout(reader, writer):  # answers in capitals
    try:
        while data := await reader.read(65536):
            writer.write(data.upper())
            await writer.drain()
    except ConnectionError:
        pass
    writer.close()


@unittest.skipUnless(HAVE_NODE, "needs node")
class TheExit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exit = Exit(CFP_ALLOW_PRIVATE="1", CFP_HELLO_TIMEOUT_MS="600")  # the local targets below are private addresses

    @classmethod
    def tearDownClass(cls):
        cls.exit.stop()

    def run_async(self, coroutine):
        return asyncio.run(asyncio.wait_for(coroutine, 60))

    # ------------------------------------------------------------ the plain HTTP side
    def test_it_announces_itself(self):
        self.assertRegex(self.exit.banner, r"cfproxy exit \d+\.\d+\.\d+: listening on \d+, ALLOW=all, configured")

    def test_the_front_page_is_a_decoy_and_everything_else_is_404(self):
        status, headers, body = self.exit.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"under construction", body)
        for path in ("/admin", "/health", PATH, PATH + "/other", "/favicon.ico"):
            self.assertEqual(self.exit.get(path)[0], 404, path)

    def test_the_health_probe_lives_under_the_secret_path(self):
        status, headers, body = self.exit.get(PATH + "/health")
        info = json.loads(body)
        self.assertEqual((status, info["ok"], info["app"], info["configured"]), (200, True, "cfproxy", True))
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertNotIn(TOKEN, body.decode())

    def test_a_bad_host_header_does_not_crash_it(self):
        raw = socket.create_connection(("127.0.0.1", self.exit.port), timeout=5)
        raw.sendall(b"GET / HTTP/1.1\r\nHost: bad host\r\nConnection: close\r\n\r\n")
        answer = raw.recv(1000)
        raw.close()
        self.assertTrue(answer.startswith(b"HTTP/1.1 400") or answer.startswith(b"HTTP/1.1 200"), answer[:40])
        self.assertEqual(self.exit.get("/")[0], 200)  # still alive

    # ------------------------------------------------------------ the tunnel
    def test_data_goes_both_ways(self):
        async def go():
            async with Target(shout) as target:
                ws, answer = await tunnel(self.exit, "127.0.0.1", target.port)
                self.assertEqual(answer, {"ok": True})
                await ws.send_binary(b"hello through the tunnel")
                op, payload = await asyncio.wait_for(ws.recv(), 10)
                self.assertEqual((op, payload), (OP_BINARY, b"HELLO THROUGH THE TUNNEL"))
                await ws.close()
        self.run_async(go())

    def test_megabytes_arrive_intact(self):
        data = os.urandom(3_000_000)

        async def go():
            async with Target(shout) as target:
                ws, _ = await tunnel(self.exit, "127.0.0.1", target.port)
                for i in range(0, len(data), 250_000):
                    await ws.send_binary(data[i:i + 250_000])
                got = b""
                while len(got) < len(data):
                    _, chunk = await asyncio.wait_for(ws.recv(), 20)
                    got += chunk
                self.assertEqual(hashlib.sha256(got).digest(), hashlib.sha256(data.upper()).digest())
                await ws.close()
        self.run_async(go())

    def test_many_tunnels_at_once_do_not_mix(self):
        async def one(target, i):
            ws, answer = await tunnel(self.exit, "127.0.0.1", target.port)
            self.assertTrue(answer["ok"])
            message = f"tunnel number {i} ".encode() * 500
            await ws.send_binary(message)
            got = b""
            while len(got) < len(message):
                got += (await asyncio.wait_for(ws.recv(), 20))[1]
            self.assertEqual(got, message.upper())
            await ws.close()

        async def go():
            async with Target(shout) as target:
                await asyncio.gather(*(one(target, i) for i in range(25)))
        self.run_async(go())

    def test_the_target_closing_ends_the_tunnel(self):
        async def hang_up(reader, writer):
            writer.write(b"bye")
            await writer.drain()
            writer.close()

        async def go():
            async with Target(hang_up) as target:
                ws, answer = await tunnel(self.exit, "127.0.0.1", target.port)
                self.assertTrue(answer["ok"])
                op, payload = await asyncio.wait_for(ws.recv(), 10)
                self.assertEqual(payload, b"bye")
                self.assertTrue(await closed_within(ws))
        self.run_async(go())

    def test_a_target_that_refuses_is_reported(self):
        async def go():
            closed = fakes.free_port()  # nothing listens there
            ws, answer = await tunnel(self.exit, "127.0.0.1", closed)
            self.assertEqual(answer["ok"], False)
            self.assertEqual(answer["err"], "connect")
        self.run_async(go())

    # ------------------------------------------------------------ who is let in
    def test_wrong_token_clock_and_garbage_are_refused_with_a_reason(self):
        async def go():
            _, wrong = await tunnel(self.exit, "127.0.0.1", 9, token="not-the-token")
            self.assertEqual(wrong, {"ok": False, "err": "auth"})
            _, late = await tunnel(self.exit, "127.0.0.1", 9, ts=int(time.time()) - 4000)
            self.assertEqual((late["err"], isinstance(late["now"], int)), ("clock", True))
            ws = await self.exit.open()
            await ws.send_text("this is not a hello")
            self.assertEqual(json.loads((await ws.recv())[1]), {"ok": False, "err": "bad-hello"})
            ws = await self.exit.open()
            await ws.send_binary(b"\x00\x01binary first")
            self.assertEqual(json.loads((await ws.recv())[1])["err"], "bad-hello")
        self.run_async(go())

    def test_the_tunnel_path_without_a_websocket_is_a_404_and_a_wrong_path_cannot_upgrade(self):
        async def go():
            with self.assertRaises(Exception):
                await self.exit.open("/some/other/path")
            with self.assertRaises(Exception):
                await self.exit.open(PATH + "/health")
        self.run_async(go())
        self.assertEqual(self.exit.get(PATH)[0], 404)

    def test_a_connection_that_stays_silent_is_dropped(self):
        async def go():
            ws = await self.exit.open()
            started = time.monotonic()
            self.assertTrue(await closed_within(ws))
            self.assertLess(time.monotonic() - started, 5)
        self.run_async(go())

    def test_a_stranger_cannot_make_it_read_a_big_message(self):
        async def go():
            ws = await self.exit.open()
            await ws.send_text("x" * 5000)  # a hello is at most 1 KB
            self.assertTrue(await closed_within(ws))
        self.run_async(go())

    def test_frames_that_are_not_masked_are_refused(self):
        raw = socket.create_connection(("127.0.0.1", self.exit.port), timeout=5)
        raw.sendall((f"GET {PATH} HTTP/1.1\r\nHost: x.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = raw.recv(1000)
        self.assertTrue(head.startswith(b"HTTP/1.1 101"), head[:40])
        raw.sendall(encode_frame(OP_TEXT, b"{}", mask=False))
        raw.settimeout(5)
        data = b""
        try:
            while True:
                part = raw.recv(1000)
                if not part:
                    break
                data += part
        except socket.timeout:
            self.fail("the server kept the connection open")
        raw.close()
        self.assertEqual(data[0] & 0x0f, OP_CLOSE)
        self.assertEqual(int.from_bytes(data[2:4], "big"), 1002)

    def test_a_websocket_request_with_a_wrong_version_is_refused(self):
        raw = socket.create_connection(("127.0.0.1", self.exit.port), timeout=5)
        raw.sendall((f"GET {PATH} HTTP/1.1\r\nHost: x.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n").encode())
        self.assertTrue(raw.recv(1000).startswith(b"HTTP/1.1 400"))
        raw.close()

    # ------------------------------------------------------------ back-pressure
    def test_a_slow_reader_makes_the_target_wait_instead_of_filling_the_memory(self):
        total = 120 * 1024 * 1024
        sent = {"bytes": 0, "done": False}

        async def flood(reader, writer):
            chunk = b"z" * 65536
            try:
                while sent["bytes"] < total:
                    writer.write(chunk)
                    await writer.drain()
                    sent["bytes"] += len(chunk)
                sent["done"] = True
            except ConnectionError:
                pass
            writer.close()

        async def go():
            async with Target(flood) as target:
                ws, answer = await tunnel(self.exit, "127.0.0.1", target.port)
                self.assertTrue(answer["ok"])
                await asyncio.sleep(1.5)  # we do not read: the exit must stop pulling from the target
                stalled = sent["bytes"]
                self.assertFalse(sent["done"], "the whole flood went into buffers")
                self.assertLess(stalled, 60 * 1024 * 1024)
                got = 0
                while got < 5 * 1024 * 1024:  # reading again lets it continue
                    got += len((await asyncio.wait_for(ws.recv(), 20))[1])
                await asyncio.sleep(0.3)
                self.assertGreater(sent["bytes"], stalled)
                await ws.close()
        self.run_async(go())


@unittest.skipUnless(HAVE_NODE, "needs node")
class WhatItRefuses(unittest.TestCase):
    def run_async(self, coroutine):
        return asyncio.run(asyncio.wait_for(coroutine, 60))

    def test_private_and_local_addresses_are_blocked(self):
        exit_ = Exit()
        self.addCleanup(exit_.stop)

        async def go():
            for host in ("127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                         "224.0.0.1", "::1", "fd12:3456::1", "fe80::1", "::ffff:127.0.0.1", "localhost",
                         "edge.railway.internal", "printer.local", "x.localhost"):
                ws, answer = await tunnel(exit_, host, 80)
                self.assertEqual((host, answer["ok"], answer["err"], answer.get("msg")), (host, False, "connect", "blocked address"))
        self.run_async(go())

    def test_a_public_address_is_not_blocked_by_the_guard(self):
        exit_ = Exit()
        self.addCleanup(exit_.stop)

        async def go():
            # no route to the internet in the test network, but the answer must be a connection failure, not the guard
            ws, answer = await tunnel(exit_, "192.0.2.1", 9)  # TEST-NET-1 is not in the blocked list
            self.assertEqual(answer["err"], "connect")
            self.assertNotEqual(answer.get("msg"), "blocked address")
        self.run_async(go())

    def test_telegram_only_refuses_everything_else(self):
        exit_ = Exit(ALLOW="telegram")
        self.addCleanup(exit_.stop)

        async def go():
            for host in ("example.com", "8.8.8.8", "127.0.0.1"):
                _, answer = await tunnel(exit_, host, 443)
                self.assertEqual(answer, {"ok": False, "err": "forbidden"}, host)
        self.run_async(go())

    def test_without_an_auth_token_everything_is_refused(self):
        exit_ = Exit(AUTH_TOKEN=None)
        self.addCleanup(exit_.stop)
        self.assertIn("NO AUTH_TOKEN", exit_.banner)
        self.assertFalse(json.loads(exit_.get(PATH + "/health")[2])["configured"])

        async def go():
            _, answer = await tunnel(exit_, "127.0.0.1", 9)
            self.assertEqual(answer, {"ok": False, "err": "not-configured"})
        self.run_async(go())

    def test_the_default_path_is_ws_and_sigterm_stops_it(self):
        exit_ = Exit(WS_PATH=None)
        self.addCleanup(exit_.stop)
        self.assertEqual(json.loads(exit_.get("/ws/health")[2])["ok"], True)
        exit_.proc.send_signal(signal.SIGTERM)
        self.assertIsNotNone(exit_.proc.wait(5))


if __name__ == "__main__":
    unittest.main()
