"""Shared test fixtures.

  * Edge          the REAL worker/index.js behind a local HTTP / HTTPS / WebSocket server (tests/edge_harness.mjs, node)
  * FakeTelegram  a Telegram data centre that speaks obfuscated2 and answers req_pq (and can echo what it is sent)
  * EchoServer    plain TCP echo
  * fixtures()    one shared set of the above, started on first use, stopped when the test run ends
"""
from __future__ import annotations

import asyncio
import atexit
import json
import os
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "lib"))

import cfp_mtproto as mt  # noqa: E402
from cfp_common import DEFAULT_TARGET, TG_DCS, TG_PORT, Settings  # noqa: E402

HAVE_NODE = shutil.which("node") is not None
HAVE_OPENSSL = shutil.which("openssl") is not None
NEED_EDGE = HAVE_NODE and HAVE_OPENSSL

TOKEN = "unit-test-token-" + "x" * 24
SECRET_HEX = "00112233445566778899aabbccddeeff"
HOST = "worker.test"
WS_PATH = "/ws-test"


def settings(**kw) -> Settings:
    base = dict(host=HOST, ws_path=WS_PATH, auth_token=TOKEN, mtproto_secret=SECRET_HEX, socks_port=0, mtproto_port=0)
    base.update(kw)
    return Settings(**base)


# ---------------------------------------------------------------- a certificate for worker.test

_cert = {}


def certificate() -> tuple:
    """(key file, cert file, client SSLContext that trusts it): self-signed, for worker.test, made once per run."""
    if not _cert:
        folder = tempfile.mkdtemp(prefix="cfp-cert-")
        atexit.register(shutil.rmtree, folder, True)
        key, crt = os.path.join(folder, "key.pem"), os.path.join(folder, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "2", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"],
                       check=True, capture_output=True)
        _cert.update(key=key, crt=crt, ctx=ssl.create_default_context(cafile=crt))
    return _cert["key"], _cert["crt"], _cert["ctx"]


# ---------------------------------------------------------------- the edge

class Edge:
    def __init__(self, auth: str = TOKEN, ws_path: str = WS_PATH, allow: str = "all", mapping: dict | None = None,
                 tls: bool = True):
        self.args = ["--auth", auth, "--ws-path", ws_path, "--allow", allow]
        if mapping:
            self.args += ["--map", ",".join(f"{a}={b}" for a, b in mapping.items())]
        if tls:
            key, crt, _ = certificate()
            self.args += ["--tls-key", key, "--tls-cert", crt]
        self.proc = None
        self.plain = self.tls = None

    def start(self) -> "Edge":
        self.proc = subprocess.Popen(["node", os.path.join(HERE, "edge_harness.mjs")] + self.args,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        if not line.startswith("READY "):
            self.stop()
            raise RuntimeError("the edge harness did not start: " + (self.proc.stderr.read() if self.proc else line))
        ports = json.loads(line[6:])
        self.plain, self.tls = ports["plain"], ports["tls"]
        return self

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc:
            for stream in (self.proc.stdout, self.proc.stderr):
                try:
                    stream.close()
                except (OSError, AttributeError):
                    pass
        self.proc = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


# ---------------------------------------------------------------- servers that stand in for the internet

class EchoServer:
    async def start(self) -> "EchoServer":
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        writer.close()


class FakeTelegram:
    """A Telegram data centre. Answers req_pq with a resPQ; after that it echoes the (decrypted) stream back."""

    def __init__(self):
        self.seen = []  # (protocol tag, dc) of every connection

    async def start(self) -> "FakeTelegram":
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        try:
            init = await reader.readexactly(64)
            opened = mt.server_handshake(init, [None])
            if opened is None:
                return
            proto, dc, dec, enc, _ = opened
            self.seen.append((proto, dc))
            buf, answered = b"", False
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                plain = dec.process(chunk)
                if answered:
                    writer.write(enc.process(plain))
                    await writer.drain()
                    continue
                buf += plain
                if buf and len(buf) >= 1 + buf[0] * 4:
                    message = buf[1:1 + buf[0] * 4]
                    nonce = message[24:40]
                    body = (bytes.fromhex("63241605") + nonce + os.urandom(16) + bytes([8]) + os.urandom(8) + bytes(3)
                            + bytes.fromhex("15c4b51c") + struct.pack("<i", 1) + os.urandom(8))
                    reply = struct.pack("<qqI", 0, (1 << 62) + 1, len(body)) + body
                    writer.write(enc.process(bytes([len(reply) // 4]) + reply))
                    await writer.drain()
                    answered = True
                    rest = buf[1 + buf[0] * 4:]
                    if rest:
                        writer.write(enc.process(rest))
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()


# ---------------------------------------------------------------- one shared set for the whole run

class Fixtures:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.echo = self._run(EchoServer().start())
        self.telegram = self._run(FakeTelegram().start())
        # every Telegram address the code may ask for lands on the fake data centre
        addresses = {f"{ip}:{TG_PORT}" for options in TG_DCS.values() for ip in options}
        addresses.add("%s:%d" % DEFAULT_TARGET)
        self.edge = Edge(mapping={a: f"127.0.0.1:{self.telegram.port}" for a in sorted(addresses)}).start()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    def stop(self):
        self.edge.stop()
        self.loop.call_soon_threadsafe(self.loop.stop)

    @property
    def tls_context(self):
        return certificate()[2]


_fixtures = None


def fixtures() -> Fixtures:
    global _fixtures
    if _fixtures is None:
        _fixtures = Fixtures()
        atexit.register(_fixtures.stop)
    return _fixtures
