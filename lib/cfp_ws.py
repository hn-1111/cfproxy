"""A small asyncio WebSocket client (RFC 6455), standard library only.

What makes it different from a normal client: it connects to a chosen IP address and port (a clean Cloudflare IP)
while the TLS server name and the Host header carry the Worker's hostname.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct

from cfp_common import USER_AGENT

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10
MAX_MESSAGE = 16 * 1024 * 1024
MAX_HEADERS = 16 * 1024


class WSError(Exception):
    pass


def mask_bytes(data: bytes, key: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return data
    stream = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")


def encode_frame(opcode: int, payload: bytes, mask: bool = True, fin: bool = True) -> bytes:
    n = len(payload)
    first = (0x80 if fin else 0) | opcode
    flag = 0x80 if mask else 0
    if n < 126:
        head = bytes([first, flag | n])
    elif n < 65536:
        head = bytes([first, flag | 126]) + struct.pack(">H", n)
    else:
        head = bytes([first, flag | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + mask_bytes(payload, key)


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


class WebSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.closed = False
        self._lock = asyncio.Lock()

    @classmethod
    async def open(cls, ip: str, port: int, host: str, path: str, *, tls: bool, timeout: float = 8.0,
                   ssl_context=None, sni: str | None = None, headers: dict | None = None) -> "WebSocket":
        ctx = (ssl_context or ssl.create_default_context()) if tls else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=(sni or host) if tls else None), timeout)
        except asyncio.TimeoutError:
            raise WSError("connect timed out")
        except (OSError, ssl.SSLError) as e:
            raise WSError(f"connect failed: {e}")
        ws = cls(reader, writer)
        try:
            await ws._handshake(host, path, timeout, headers or {})
        except BaseException:
            writer.close()
            raise
        return ws

    async def _handshake(self, host: str, path: str, timeout: float, headers: dict) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13", f"User-Agent: {USER_AGENT}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        try:
            self.writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
            await asyncio.wait_for(self.writer.drain(), timeout)
            head = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), timeout)
        except asyncio.TimeoutError:
            raise WSError("handshake timed out")
        except asyncio.LimitOverrunError:
            raise WSError("handshake answer too large")
        except (asyncio.IncompleteReadError, OSError, ssl.SSLError) as e:
            raise WSError(f"handshake failed: {e or 'connection closed'}")
        if len(head) > MAX_HEADERS:
            raise WSError("handshake answer too large")
        text = head.decode("latin-1")
        status = text.split("\r\n", 1)[0]
        parts = status.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            raise WSError(f"no WebSocket upgrade ({status.strip()[:60]})")
        got = ""
        for line in text.split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "sec-websocket-accept":
                got = value.strip()
        if got != accept_key(key):
            raise WSError("bad Sec-WebSocket-Accept")

    # ---- sending

    async def _send(self, opcode: int, payload: bytes) -> None:
        if self.closed:
            raise WSError("connection closed")
        frame = encode_frame(opcode, payload, mask=True)
        async with self._lock:
            try:
                self.writer.write(frame)
                await self.writer.drain()
            except (OSError, ssl.SSLError) as e:
                self.closed = True
                raise WSError(f"send failed: {e}")

    async def send_text(self, text: str) -> None:
        await self._send(OP_TEXT, text.encode("utf-8"))

    async def send_binary(self, data: bytes) -> None:
        await self._send(OP_BINARY, data)

    async def ping(self) -> None:
        await self._send(OP_PING, b"")

    # ---- receiving

    async def _read_frame(self):
        h = await self.reader.readexactly(2)
        fin, opcode = bool(h[0] & 0x80), h[0] & 0x0F
        masked, n = bool(h[1] & 0x80), h[1] & 0x7F
        if n == 126:
            n = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", await self.reader.readexactly(8))[0]
        if n > MAX_MESSAGE:
            raise WSError("frame too large")
        key = await self.reader.readexactly(4) if masked else None
        payload = await self.reader.readexactly(n) if n else b""
        return fin, opcode, (mask_bytes(payload, key) if key else payload)

    async def recv(self):
        """The next data message as (opcode, payload), or None once the connection is closed."""
        message, first = bytearray(), None
        while True:
            try:
                fin, op, payload = await self._read_frame()
            except (asyncio.IncompleteReadError, OSError, ssl.SSLError):
                self.closed = True
                return None
            if op == OP_PING:
                try:
                    await self._send(OP_PONG, payload)
                except WSError:
                    return None
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                if not self.closed:
                    self.closed = True
                    try:
                        self.writer.write(encode_frame(OP_CLOSE, payload[:2], mask=True))
                    except (OSError, ssl.SSLError):
                        pass
                return None
            if op in (OP_TEXT, OP_BINARY):
                first, message = op, bytearray(payload)
            elif op == OP_CONT and first is not None:
                message += payload
            else:
                raise WSError("unexpected frame")
            if len(message) > MAX_MESSAGE:
                raise WSError("message too large")
            if fin:
                return first, bytes(message)

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.writer.write(encode_frame(OP_CLOSE, struct.pack(">H", 1000), mask=True))
            except (OSError, ssl.SSLError, RuntimeError):
                pass
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 1.0)
        except Exception:
            pass
