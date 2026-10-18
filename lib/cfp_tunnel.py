"""A tunnel to host:port through the Worker, and the pool of clean Cloudflare endpoints it can use."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from cfp_common import TLS_PORTS, Settings
from cfp_ws import OP_BINARY, OP_TEXT, WebSocket, WSError

PING_SECONDS = 25.0


class TunnelError(Exception):
    """The tunnel could not be opened (network, handshake, ...). The endpoint is probably the problem."""


class TunnelRefused(TunnelError):
    """The Worker answered but said no (wrong token, target unreachable, ...). Another endpoint would not help."""

    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


def sign(token: str, ts: int, host: str, port: int) -> str:
    return hmac.new(token.encode(), f"{ts}|{host}|{port}".encode(), hashlib.sha256).hexdigest()


def make_hello(token: str, host: str, port: int, ts: int | None = None) -> str:
    ts = int(time.time()) if ts is None else ts
    return json.dumps({"v": 1, "ts": ts, "sig": sign(token, ts, host, port), "host": host, "port": port},
                      separators=(",", ":"))


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int
    tls: bool = True
    ms: float = 0.0
    colo: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Endpoint":
        port = int(d["port"])
        tls = d["tls"] if "tls" in d else port in TLS_PORTS
        return cls(ip=d["ip"], port=port, tls=bool(tls), ms=float(d.get("tunnel_ms") or d.get("ms") or 0),
                   colo=d.get("colo") or "")

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


def explain(reply: dict) -> str:
    err = reply.get("err", "")
    if err == "auth":
        return "wrong AUTH_TOKEN (the Worker has a different one: run './cfproxy.sh setup' and 'deploy' again)"
    if err == "clock":
        skew = int(time.time()) - int(reply.get("now", 0)) if reply.get("now") else None
        return "the clocks differ too much" + (f" (yours is {skew}s off)" if skew is not None else "") + ": fix the time"
    if err == "not-configured":
        return "the Worker has no AUTH_TOKEN: deploy again"
    if err == "forbidden":
        return "the Worker does not allow this target (ALLOW=telegram only lets Telegram addresses through)"
    if err == "connect":
        return f"the Worker could not reach the target ({reply.get('msg', 'connect failed')})"
    if err == "bad-hello":
        return "the Worker did not understand the request (version mismatch?)"
    return f"refused ({err or 'unknown'})"


class Tunnel:
    """An open, authenticated tunnel: send() bytes in, recv() bytes out (None when it is closed)."""

    def __init__(self, ws: WebSocket, endpoint: Endpoint):
        self.ws = ws
        self.endpoint = endpoint
        self._pinger = None

    @classmethod
    async def open(cls, endpoint: Endpoint, st: Settings, host: str, port: int, timeout: float = 8.0) -> "Tunnel":
        try:
            ws = await WebSocket.open(endpoint.ip, endpoint.port, st.host, st.ws_path, tls=endpoint.tls,
                                      timeout=timeout, ssl_context=st.ssl_context)
        except WSError as e:
            raise TunnelError(f"{endpoint}: {e}")
        try:
            await ws.send_text(make_hello(st.auth_token, host, port))
            message = await asyncio.wait_for(ws.recv(), timeout)
            if message is None:
                raise TunnelError(f"{endpoint}: closed during the handshake")
            op, payload = message
            try:
                reply = json.loads(payload) if op == OP_TEXT else {}
            except ValueError:
                reply = {}
            if not reply.get("ok"):
                raise TunnelRefused(explain(reply), reply.get("err", ""))
        except asyncio.TimeoutError:
            await ws.close()
            raise TunnelError(f"{endpoint}: no answer to the handshake")
        except WSError as e:
            await ws.close()
            raise TunnelError(f"{endpoint}: {e}")
        except BaseException:
            await ws.close()
            raise
        tunnel = cls(ws, endpoint)
        tunnel._pinger = asyncio.ensure_future(tunnel._keepalive())
        return tunnel

    async def _keepalive(self) -> None:
        try:
            while not self.ws.closed:
                await asyncio.sleep(PING_SECONDS)
                await self.ws.ping()
        except (WSError, asyncio.CancelledError):
            pass

    async def send(self, data: bytes) -> None:
        try:
            await self.ws.send_binary(data)
        except WSError as e:
            raise TunnelError(str(e))

    async def recv(self):
        while True:
            try:
                message = await self.ws.recv()
            except WSError:
                return None
            if message is None:
                return None
            op, payload = message
            if op == OP_BINARY:
                return payload

    async def close(self) -> None:
        if self._pinger:
            self._pinger.cancel()
        await self.ws.close()


class EndpointPool:
    """The clean endpoints, best first. Failed ones are skipped for a while; the rest are used in turn."""

    def __init__(self, endpoints, cooldown: float = 60.0):
        self.endpoints = list(endpoints)
        if not self.endpoints:
            raise ValueError("no endpoints")
        self.cooldown = cooldown
        self._bad_until = {}
        self._turn = 0

    def pick(self, count: int) -> list:
        now = time.monotonic()
        healthy = [e for e in self.endpoints if self._bad_until.get(e, 0) <= now]
        pool = healthy or list(self.endpoints)  # everything failed lately: try them all again
        start = self._turn % len(pool)
        self._turn += 1
        return (pool[start:] + pool[:start])[:count]

    def bad(self, endpoint: Endpoint) -> None:
        self._bad_until[endpoint] = time.monotonic() + self.cooldown

    def good(self, endpoint: Endpoint) -> None:
        self._bad_until.pop(endpoint, None)


async def open_tunnel(pool: EndpointPool, st: Settings, host: str, port: int, attempts: int = 3,
                      timeout: float = 8.0) -> Tunnel:
    problems = []
    for endpoint in pool.pick(attempts):
        try:
            tunnel = await Tunnel.open(endpoint, st, host, port, timeout)
        except TunnelRefused:
            raise
        except TunnelError as e:
            pool.bad(endpoint)
            problems.append(str(e))
            continue
        pool.good(endpoint)
        return tunnel
    raise TunnelError("; ".join(problems) or "no endpoint")

