"""The Worker's own rules, through the real worker/index.js behind the local edge: who may open a tunnel and to where,
what a stranger sees, and the unit tests of its small functions (worker_unit.mjs)."""
import asyncio
import json
import os
import subprocess
import time
import unittest
import urllib.error
import urllib.request

import helpers
from helpers import HAVE_NODE, HOST, TOKEN, WS_PATH, fixtures, settings

from cfp_tunnel import Endpoint, Tunnel, TunnelRefused, make_hello, sign
from cfp_ws import OP_TEXT, WebSocket

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(port: int, path: str):
    """(status, headers, body) of a plain GET against the local edge."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Host": HOST})
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


async def raw_hello(port: int, text: str, path: str = WS_PATH) -> dict:
    """Opens the WebSocket, sends `text` as the first message and returns the Worker's answer."""
    ws = await WebSocket.open("127.0.0.1", port, HOST, path, tls=False, timeout=5)
    try:
        await ws.send_text(text)
        message = await asyncio.wait_for(ws.recv(), 5)
        return json.loads(message[1]) if message and message[0] == OP_TEXT else {}
    finally:
        await ws.close()


@unittest.skipUnless(HAVE_NODE, "needs node")
class FunctionsOfTheWorker(unittest.TestCase):
    def test_node_unit_tests(self):
        done = subprocess.run(["node", os.path.join(HERE, "worker_unit.mjs")], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("passed", done.stdout)


@unittest.skipUnless(HAVE_NODE, "needs node")
class WhatAStrangerSees(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.edge = helpers.Edge(tls=False).start()

    @classmethod
    def tearDownClass(cls):
        cls.edge.stop()

    def test_the_home_page_is_a_harmless_decoy(self):
        status, headers, body = fetch(self.edge.plain, "/")
        self.assertEqual(status, 200)
        self.assertIn(b"under construction", body)
        self.assertNotIn(b"cfproxy", body.lower())

    def test_everything_else_is_a_plain_404(self):
        for path in ("/health", "/ws", WS_PATH, "/admin", f"{WS_PATH}/other", "/ws/health"):
            self.assertEqual(fetch(self.edge.plain, path)[0], 404, path)

    def test_the_probe_answers_only_under_the_secret_path(self):
        status, headers, body = fetch(self.edge.plain, f"{WS_PATH}/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual((data["ok"], data["app"], data["configured"]), (True, "cfproxy", True))
        self.assertAlmostEqual(data["ts"], time.time(), delta=60)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertNotIn(TOKEN.encode(), body)

    def test_a_websocket_on_any_other_path_is_not_a_tunnel(self):
        with self.assertRaises(Exception) as caught:
            asyncio.run(raw_hello(self.edge.plain, "{}", path="/elsewhere"))
        self.assertIn("WebSocket", str(caught.exception) + type(caught.exception).__name__)


@unittest.skipUnless(HAVE_NODE, "needs node")
class WhoMayOpenATunnel(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()
        cls.plain = cls.fx.edge.plain

    async def test_garbage_is_not_a_hello(self):
        for text in ("hello", "{}", "[]", json.dumps({"v": 1, "ts": 1, "sig": "x", "host": "a", "port": 1}),
                     json.dumps({"v": 1, "ts": int(time.time()), "sig": "0" * 64, "host": "bad host", "port": 443})):
            answer = await raw_hello(self.plain, text)
            self.assertEqual((answer.get("ok"), answer.get("err")), (False, "bad-hello"), text)

    async def test_a_wrong_signature_is_refused(self):
        hello = make_hello("not-the-token", "127.0.0.1", self.fx.echo.port)
        answer = await raw_hello(self.plain, hello)
        self.assertEqual((answer["ok"], answer["err"]), (False, "auth"))

    async def test_the_target_is_part_of_the_signature(self):
        hello = json.loads(make_hello(TOKEN, "127.0.0.1", self.fx.echo.port))
        hello["port"] = hello["port"] + 1
        answer = await raw_hello(self.plain, json.dumps(hello))
        self.assertEqual(answer["err"], "auth")

    async def test_a_clock_that_is_off_is_reported_with_the_workers_time(self):
        old = int(time.time()) - 3600
        hello = json.dumps({"v": 1, "ts": old, "sig": sign(TOKEN, old, "127.0.0.1", self.fx.echo.port),
                            "host": "127.0.0.1", "port": self.fx.echo.port}, separators=(",", ":"))
        answer = await raw_hello(self.plain, hello)
        self.assertEqual((answer["ok"], answer["err"]), (False, "clock"))
        self.assertAlmostEqual(answer["now"], time.time(), delta=60)

    async def test_a_binary_frame_cannot_start_a_tunnel(self):
        ws = await WebSocket.open("127.0.0.1", self.plain, HOST, WS_PATH, tls=False, timeout=5)
        try:
            await ws.send_binary(b"\x00" * 10)
            message = await asyncio.wait_for(ws.recv(), 5)
            self.assertEqual(json.loads(message[1])["err"], "bad-hello")
        finally:
            await ws.close()

    async def test_an_unreachable_target_says_connect(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        with self.assertRaises(TunnelRefused) as caught:
            await Tunnel.open(Endpoint("127.0.0.1", self.plain, tls=False), settings(), "127.0.0.1", dead, 5)
        self.assertEqual(caught.exception.code, "connect")

    async def test_the_right_token_reaches_the_target_and_the_data_comes_back(self):
        tunnel = await Tunnel.open(Endpoint("127.0.0.1", self.plain, tls=False), settings(), "127.0.0.1", self.fx.echo.port, 5)
        try:
            await tunnel.send(b"ping")
            self.assertEqual(await asyncio.wait_for(tunnel.recv(), 5), b"ping")
        finally:
            await tunnel.close()


@unittest.skipUnless(HAVE_NODE, "needs node")
class TheMtprotoOnlyWorker(unittest.IsolatedAsyncioTestCase):
    """ALLOW=telegram: the Worker may only reach Telegram's address ranges."""

    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()
        cls.edge = helpers.Edge(allow="telegram", tls=False,
                                mapping={"149.154.167.51:443": f"127.0.0.1:{cls.fx.telegram.port}"}).start()

    @classmethod
    def tearDownClass(cls):
        cls.edge.stop()

    async def test_anything_but_telegram_is_forbidden(self):
        for host, port in (("127.0.0.1", self.fx.echo.port), ("example.com", 443), ("8.8.8.8", 53),
                           ("149.154.176.1", 443)):
            with self.assertRaises(TunnelRefused, msg=host) as caught:
                await Tunnel.open(Endpoint("127.0.0.1", self.edge.plain, tls=False), settings(), host, port, 5)
            self.assertEqual(caught.exception.code, "forbidden", host)

    async def test_telegram_is_allowed(self):
        tunnel = await Tunnel.open(Endpoint("127.0.0.1", self.edge.plain, tls=False), settings(), "149.154.167.51", 443, 5)
        await tunnel.close()


@unittest.skipUnless(HAVE_NODE, "needs node")
class AWorkerWithoutItsToken(unittest.IsolatedAsyncioTestCase):
    async def test_it_says_so_and_refuses_everything(self):
        with helpers.Edge(auth="", tls=False) as edge:
            data = json.loads(fetch(edge.plain, f"{WS_PATH}/health")[2])
            self.assertEqual((data["ok"], data["configured"]), (True, False))
            answer = await raw_hello(edge.plain, make_hello("", "127.0.0.1", 80))
            self.assertEqual(answer["err"], "not-configured")
            answer = await raw_hello(edge.plain, make_hello("anything", "127.0.0.1", 80))
            self.assertEqual(answer["err"], "not-configured")


if __name__ == "__main__":
    unittest.main()
