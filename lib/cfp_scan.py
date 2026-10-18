"""Finds the Cloudflare IPs and ports that work from YOUR network, then proves them with a real tunnel.

  1. pick IPs        random addresses from Cloudflare's ranges (one per /24 first), or your own list
  2. probe           every IP x every port: TCP connect, TLS (on the HTTPS ports), then GET <WS_PATH>/health with the
                     Worker's Host header. Only an edge that really answers for your Worker survives.
  3. verify          the best candidates open an authenticated tunnel to a Telegram data centre and get an answer
                     to req_pq: the whole path (clean IP -> Cloudflare -> Worker -> Telegram) is proven, and timed.

The result (best first) goes to endpoints.json; `serve` and `links` read it. Standard library only.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import re
import ssl
import sys
import time
import urllib.request

from cfp_common import (ALL_PORTS, CF_RANGES_V4, DEFAULT_TARGET, TLS_PORTS, USER_AGENT, ConfigError, Settings, bold,
                        dim, home, info, say, warn)
from cfp_mtproto import probe_telegram
from cfp_tunnel import Endpoint, Tunnel, TunnelError, TunnelRefused

DEFAULT_COUNT = 200      # random IPs to try
DEFAULT_VERIFY = 40      # candidates that get the full tunnel test
DEFAULT_KEEP = 20        # endpoints kept in the result
DEFAULT_CONCURRENCY = 80
RANGES_URL = "https://www.cloudflare.com/ips-v4"
MAX_BODY = 8192


# ---------------------------------------------------------------- which IPs

def ranges_path() -> str:
    import os
    return os.path.join(home(), "ranges.txt")


def load_ranges() -> list:
    """The ranges `scan --update-ranges` saved, else the ones built into the program."""
    try:
        with open(ranges_path(), encoding="utf-8") as f:
            found = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if found:
            return found
    except OSError:
        pass
    return list(CF_RANGES_V4)


def update_ranges(url: str = RANGES_URL, timeout: float = 15.0) -> int:
    """Downloads Cloudflare's current IPv4 list. Returns how many ranges it holds."""
    import os
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read(100_000).decode("utf-8", "replace")
    found = []
    for line in text.split():
        try:
            net = ipaddress.ip_network(line.strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            found.append(str(net))
    if not found:
        raise ConfigError(f"{url} did not hold a list of IPv4 ranges")
    os.makedirs(home(), exist_ok=True)
    with open(ranges_path(), "w", encoding="utf-8") as f:
        f.write("# Cloudflare IPv4 ranges, fetched %s\n%s\n" % (time.strftime("%Y-%m-%d"), "\n".join(found)))
    return len(found)


def parse_ip_text(text: str) -> list:
    """The IPs and CIDR ranges in a file's text (one per line, or separated by commas / spaces; # starts a
    comment). sample_ips() then expands the small ranges and samples the big ones."""
    items = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        items += [p for p in re.split(r"[,\s]+", line.strip()) if p]
    return items


def sample_ips(ranges, count: int, rng: random.Random | None = None) -> list:
    """`count` addresses spread over as many different /24 blocks as possible (a single IP stays as it is)."""
    rng = rng or random.Random()
    blocks, fixed = [], []
    for item in ranges:
        try:
            net = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            warn(f"'{item}' is not an IP address or range: skipped")
            continue
        if net.version != 4:
            continue
        if net.prefixlen >= 32:
            fixed.append(str(net.network_address))
        elif net.prefixlen >= 24:
            fixed += [str(h) for h in net.hosts()]
        else:
            blocks += list(net.subnets(new_prefix=24))
    rng.shuffle(blocks)
    picked = []
    for block in blocks[:max(0, count - len(fixed))]:
        base = int(block.network_address)
        picked.append(str(ipaddress.ip_address(base + rng.randint(1, 254))))
    out = fixed + picked
    rng.shuffle(out)
    return out[:max(count, len(fixed))]


def port_plans(ports) -> list:
    """[(port, tls)]: the Cloudflare HTTPS ports speak TLS, everything else is plain HTTP."""
    return [(p, p in TLS_PORTS) for p in ports]


# ---------------------------------------------------------------- stage 1: connect, TLS, health

_context = None


def client_context(st: Settings):
    global _context
    if st.ssl_context is not None:
        return st.ssl_context
    if _context is None:
        _context = ssl.create_default_context()
    return _context


def parse_response(raw: bytes):
    """(status, headers, body) of a small HTTP/1.x response, or None while it is incomplete."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return 0, {}, b""
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return int(parts[1]), headers, body


def dechunk(body: bytes) -> bytes:
    """The payload of a Transfer-Encoding: chunked body."""
    out = b""
    while body:
        size_line, sep, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if not sep or size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out


async def probe_pair(ip: str, port: int, tls: bool, st: Settings, timeout: float) -> dict:
    """One IP on one port. {"ok": bool, "ms": TCP+TLS+HTTP round trip, "colo": "FRA" | "", "error": str}"""
    start = time.perf_counter()
    writer = None
    try:
        ctx = client_context(st) if tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=st.host if tls else None), timeout)
        health = st.ws_path.rstrip("/") + "/health"
        writer.write((f"GET {health} HTTP/1.1\r\nHost: {st.host}\r\nUser-Agent: {USER_AGENT}\r\n"
                      "Accept: application/json\r\nConnection: close\r\n\r\n").encode())
        await asyncio.wait_for(writer.drain(), timeout)
        raw = b""
        deadline = start + timeout
        while len(raw) < MAX_BODY:
            parsed = parse_response(raw)
            if parsed and parsed[0] and "content-length" in parsed[1] and len(parsed[2]) >= int(parsed[1]["content-length"] or 0):
                break
            left = deadline - time.perf_counter()
            if left <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(4096), left)
            if not chunk:
                break
            raw += chunk
        parsed = parse_response(raw)
    except asyncio.TimeoutError:
        return {"ok": False, "ms": 0.0, "colo": "", "error": "timeout"}
    except (OSError, ssl.SSLError, ValueError) as e:
        return {"ok": False, "ms": 0.0, "colo": "", "error": type(e).__name__}
    finally:
        if writer is not None:
            writer.close()
    ms = (time.perf_counter() - start) * 1000
    if not parsed or parsed[0] != 200:
        return {"ok": False, "ms": ms, "colo": "", "error": f"HTTP {parsed[0] if parsed else '?'}"}
    payload = dechunk(parsed[2]) if "chunked" in parsed[1].get("transfer-encoding", "") else parsed[2]
    try:
        body = json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        body = None
    if not isinstance(body, dict) or not body.get("ok"):
        return {"ok": False, "ms": ms, "colo": "", "error": "not the Worker"}
    colo = str(body.get("colo") or "")
    if not colo:  # the CF-RAY header ends with the location code
        match = re.search(r"-([A-Z]{3})$", parsed[1].get("cf-ray", ""))
        colo = match.group(1) if match else ""
    return {"ok": True, "ms": ms, "colo": colo, "error": "" if body.get("configured") else "no-auth-token"}


async def gather_or_cancel(coroutines) -> None:
    """Runs them all; when one raises, the others are cancelled (not left running in the background)."""
    tasks = [asyncio.ensure_future(c) for c in coroutines]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def probe_all(ips, plans, st: Settings, timeout: float, concurrency: int, progress=None) -> list:
    """Every (ip, port) pair, `concurrency` at a time. Returns the pairs that answered, fastest first."""
    pairs = [(ip, port, tls) for ip in ips for port, tls in plans]
    gate = asyncio.Semaphore(concurrency)
    alive, done = [], 0

    async def one(ip, port, tls):
        nonlocal done
        async with gate:
            result = await probe_pair(ip, port, tls, st, timeout)
        done += 1
        if result["ok"]:
            alive.append({"ip": ip, "port": port, "tls": tls, "ms": round(result["ms"], 1), "colo": result["colo"],
                          "note": result["error"]})
        if progress:
            progress("probe", done, len(pairs), len(alive))

    await gather_or_cancel([one(*pair) for pair in pairs])
    alive.sort(key=lambda r: r["ms"])
    return alive


def shortlist(alive: list, limit: int) -> list:
    """The best `limit` pairs, spread over as many different IPs as possible: every IP's fastest port first, then
    every IP's second fastest, and so on."""
    by_ip = {}
    for row in alive:  # `alive` is sorted: each IP's list is sorted too
        by_ip.setdefault(row["ip"], []).append(row)
    ordered = sorted(by_ip.values(), key=lambda rows: rows[0]["ms"])
    out, rank = [], 0
    while len(out) < limit and any(len(rows) > rank for rows in ordered):
        for rows in ordered:
            if len(rows) > rank and len(out) < limit:
                out.append(rows[rank])
        rank += 1
    return out


# ---------------------------------------------------------------- stage 2: a real tunnel

async def tunnel_once(endpoint: Endpoint, st: Settings, timeout: float, target=DEFAULT_TARGET) -> dict:
    """Opens a tunnel to a Telegram data centre through `endpoint` and times a req_pq round trip.
    Raises TunnelRefused when the Worker itself says no (the same answer for every endpoint)."""
    start = time.perf_counter()
    try:
        tunnel = await Tunnel.open(endpoint, st, target[0], target[1], timeout)
    except TunnelRefused:
        raise
    except TunnelError as e:
        return {"ok": False, "ms": 0.0, "error": str(e)}
    try:
        result = await probe_telegram(tunnel.send, tunnel.recv, dc=2, timeout=timeout)
    finally:
        await tunnel.close()
    return {"ok": result["ok"], "ms": (time.perf_counter() - start) * 1000, "error": result["error"]}


async def verify_all(candidates, st: Settings, timeout: float, concurrency: int, samples: int = 2,
                     progress=None) -> tuple:
    """(verified candidates with tunnel_ms, best first; {reason: how many candidates failed with it})"""
    gate = asyncio.Semaphore(max(1, concurrency // 4))
    verified, done, reasons = [], 0, {}

    async def one(row):
        nonlocal done
        endpoint = Endpoint(ip=row["ip"], port=row["port"], tls=row["tls"])
        times, error = [], ""
        async with gate:
            for _ in range(samples):
                result = await tunnel_once(endpoint, st, timeout)
                if result["ok"]:
                    times.append(result["ms"])
                else:
                    error = result["error"]
        done += 1
        if times:
            verified.append({**row, "tunnel_ms": round(min(times), 1)})
        else:
            reasons[error] = reasons.get(error, 0) + 1
        if progress:
            progress("verify", done, len(candidates), len(verified))

    await gather_or_cancel([one(row) for row in candidates])
    verified.sort(key=lambda r: r["tunnel_ms"])
    return verified, reasons


# ---------------------------------------------------------------- the whole scan

async def scan(st: Settings, ips, plans, *, verify: int = DEFAULT_VERIFY, keep: int = DEFAULT_KEEP,
               timeout: float = 5.0, concurrency: int = DEFAULT_CONCURRENCY, tunnel: bool = True,
               progress=None) -> tuple:
    """Returns (endpoints, meta). `endpoints` is best first; each is {ip, port, tls, ms, tunnel_ms, colo}."""
    alive = await probe_all(ips, plans, st, timeout, concurrency, progress)
    meta = {"host": st.host, "ips_tried": len(ips), "ports": [p for p, _ in plans], "answered": len(alive),
            "verified": False}
    if not alive:
        return [], meta
    if any(r["note"] == "no-auth-token" for r in alive[:1]):
        meta["warning"] = "the Worker answers but has no AUTH_TOKEN: deploy again"
    if not tunnel:
        return alive[:keep], meta
    best, reasons = await verify_all(shortlist(alive, verify), st, max(timeout, 8.0), concurrency, progress=progress)
    meta["verified"] = True
    meta["tunnel_ok"] = len(best)
    if not best and reasons:
        meta["tunnel_error"] = max(reasons, key=reasons.get)
    return best[:keep], meta


class Progress:
    """One updating line on stderr (a line per step when stderr is not a terminal)."""

    def __init__(self):
        self.tty = sys.stderr.isatty()
        self.last = {}

    def __call__(self, stage: str, done: int, total: int, good: int) -> None:
        label = {"probe": "probing IP x port", "verify": "opening tunnels"}[stage]
        text = f"  {label}: {done}/{total}  ({good} good)"
        if self.tty:
            sys.stderr.write("\r" + text + " " * 6)
            if done >= total:
                sys.stderr.write("\n")
            sys.stderr.flush()
        elif done >= total or done - self.last.get(stage, 0) >= max(1, total // 5):
            self.last[stage] = done
            say(text)


def format_table(endpoints: list) -> list:
    rows = [f"  {'#':>2}  {'IP':<16} {'PORT':>5}  {'TLS':<3}  {'COLO':<4}  {'PROBE':>8}  {'TUNNEL':>8}"]
    for i, e in enumerate(endpoints, 1):
        tunnel = f"{e['tunnel_ms']:.0f} ms" if e.get("tunnel_ms") else "-"
        rows.append(f"  {i:>2}  {e['ip']:<16} {e['port']:>5}  {'yes' if e['tls'] else 'no':<3}  "
                    f"{e.get('colo') or '-':<4}  {e['ms']:>5.0f} ms  {tunnel:>8}")
    return rows


def endpoint_lines(endpoints: list) -> str:
    """ip:port, one per line (what other tools that take a clean-IP list want)."""
    return "".join(f"{e['ip']}:{e['port']}\n" for e in endpoints)


def explain_empty(meta: dict) -> str:
    return ("no IP answered for your Worker. Check that it is deployed ('./cfproxy.sh status'), that WORKER_HOST is "
            f"right ({meta.get('host') or 'not set'}), and try another network or --ports tls / plain.")
