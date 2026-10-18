/**
 * cfproxy - Cloudflare Worker (the same file also works as a Pages `_worker.js`).
 *
 * A Worker cannot listen for raw TCP, so it cannot *be* an MTProto or SOCKS5 server. What it can do is the exit half
 * of one: accept an authenticated WebSocket, open an outbound TCP socket with connect() and copy bytes both ways.
 * The client half (lib/cfp_bridge.py) speaks SOCKS5 / MTProto on your own machine and reaches this Worker through
 * clean Cloudflare IPs on any of Cloudflare's HTTP(S) ports.
 *
 * Wire protocol (one WebSocket = one TCP connection):
 *   client -> text   {"v":1,"ts":<unix seconds>,"sig":"<hex>","host":"<target>","port":<n>}
 *                    sig = HMAC-SHA256(AUTH_TOKEN, "<ts>|<host>|<port>")
 *   worker -> text   {"ok":true}  or  {"ok":false,"err":"<reason>"} (and the socket closes)
 *   then             binary frames in both directions = the raw TCP stream
 *
 * Everything else is a decoy: "/" shows a harmless page, any other path is a 404. The only other thing that answers
 * is the health probe the scanner uses, and it lives UNDER the secret path (<WS_PATH>/health), so nobody who does
 * not know the path can tell that this is a tunnel.
 *
 * Settings (Worker secrets / variables):
 *   AUTH_TOKEN  required, the shared secret
 *   WS_PATH     path of the tunnel endpoint, default /ws
 *   ALLOW       "all" (default) or "telegram" (only Telegram's address ranges: an MTProto-only exit)
 */
import { connect } from "cloudflare:sockets";

const VERSION = "1.0.0";
const APP = "cfproxy";
const SKEW_SECONDS = 300;
const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;

// Telegram's published address ranges (https://core.telegram.org/resources/cidr.txt), used by ALLOW=telegram
const TG_V4 = [
  ["91.105.192.0", 23], ["91.108.4.0", 22], ["91.108.8.0", 22], ["91.108.12.0", 22], ["91.108.16.0", 22],
  ["91.108.20.0", 22], ["91.108.56.0", 22], ["95.161.64.0", 20], ["149.154.160.0", 20], ["185.76.151.0", 24],
];
const TG_V6 = ["2001:67c:4e8:", "2001:b28:f23d:", "2001:b28:f23f:", "2a0a:f280:"];

const DECOY = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Welcome</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#333}</style></head>
<body><h1>Welcome</h1><p>This site is under construction.</p></body></html>`;

const encoder = new TextEncoder();

function ipv4ToInt(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function inCidr(ip, base, bits) {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
}

export function isTelegramHost(host) {
  const v4 = ipv4ToInt(host);
  if (v4 !== null) return TG_V4.some(([base, bits]) => inCidr(v4, ipv4ToInt(base), bits));
  const lower = host.toLowerCase();
  return TG_V6.some((prefix) => lower.startsWith(prefix));
}

export function targetAllowed(env, host, port) {
  const mode = String(env.ALLOW || "all").toLowerCase();
  if (mode === "telegram") return isTelegramHost(host);
  return port >= 1 && port <= 65535;
}

export function parseHello(data) {
  if (typeof data !== "string" || data.length > 1024) return null;
  let h;
  try { h = JSON.parse(data); } catch { return null; }
  if (!h || typeof h !== "object") return null;
  const port = h.port, ts = h.ts;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (!Number.isInteger(ts)) return null;
  if (typeof h.host !== "string" || !HOST_RE.test(h.host)) return null;
  if (typeof h.sig !== "string" || !/^[0-9a-f]{64}$/.test(h.sig)) return null;
  return { ts, port, host: h.host, sig: h.sig };
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** "" when the hello is valid, else the reason. crypto.subtle.verify compares in constant time. */
export async function checkHello(env, hello, nowMs) {
  if (!env.AUTH_TOKEN) return "not-configured";
  if (Math.abs(nowMs / 1000 - hello.ts) > SKEW_SECONDS) return "clock";
  const key = await crypto.subtle.importKey("raw", encoder.encode(String(env.AUTH_TOKEN)),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const good = await crypto.subtle.verify("HMAC", key, hexToBytes(hello.sig),
    encoder.encode(`${hello.ts}|${hello.host}|${hello.port}`));
  return good ? "" : "auth";
}

function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

/**
 * Runs one tunnel on an accepted WebSocket. `connectFn` is cloudflare:sockets connect (a fake one in the tests).
 */
export function attachSession(ws, env, connectFn, now = Date.now) {
  let state = 0; // 0 waiting for the hello, 1 connecting, 2 relaying, 3 finished
  let socket = null;
  let writer = null;
  let queue = Promise.resolve(); // the messages are handled one after the other, in order

  const finish = (code = 1000, reason = "") => {
    if (state === 3) return;
    state = 3;
    try { socket && socket.close().catch(() => {}); } catch { /* already closed */ }
    try { ws.close(code, reason.slice(0, 100)); } catch { /* already closed */ }
  };

  const refuse = (err, extra = {}) => {
    try { ws.send(JSON.stringify({ ok: false, err, ...extra })); } catch { /* gone */ }
    finish(1000, "refused");
  };

  async function pump() {
    const reader = socket.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) ws.send(value);
      }
    } catch { /* the remote side reset the connection */ }
    finish(1000, "eof");
  }

  async function onMessage(data) {
    if (state === 2) {
      const bytes = toBytes(data);
      if (bytes) await writer.write(bytes);
      return; // text frames after the hello (keep-alives) are ignored
    }
    if (state !== 0) return;
    state = 1;
    const hello = parseHello(data);
    if (!hello) return refuse("bad-hello");
    const bad = await checkHello(env, hello, now());
    if (bad) return refuse(bad, bad === "clock" ? { now: Math.floor(now() / 1000) } : {});
    if (!targetAllowed(env, hello.host, hello.port)) return refuse("forbidden");
    try {
      socket = connectFn({ hostname: hello.host, port: hello.port }, { secureTransport: "off", allowHalfOpen: false });
      await socket.opened;
    } catch (e) {
      return refuse("connect", { msg: String((e && e.message) || e).slice(0, 120) });
    }
    if (state === 3) { try { socket.close(); } catch { /* ignore */ } return; }
    writer = socket.writable.getWriter();
    state = 2;
    ws.send(JSON.stringify({ ok: true }));
    pump();
  }

  ws.addEventListener("message", (event) => {
    queue = queue.then(() => onMessage(event.data)).catch(() => finish(1011, "relay error"));
  });
  ws.addEventListener("close", () => finish());
  ws.addEventListener("error", () => finish());
}

export function wsPathOf(env) {
  const p = String(env.WS_PATH || "/ws").trim();
  return p.startsWith("/") ? p : `/${p}`;
}

/** <WS_PATH>/health: only someone who knows the secret path finds the probe. */
export function healthPathOf(env) {
  return `${wsPathOf(env).replace(/\/+$/, "")}/health`;
}

/** The plain HTTP side: a health probe for the scanner (under the secret path) and a harmless page for the rest. */
export function handleHttp(request, env) {
  const url = new URL(request.url);
  if (url.pathname === healthPathOf(env)) {
    const body = {
      ok: true, app: APP, v: VERSION, ts: Math.floor(Date.now() / 1000),
      colo: (request.cf && request.cf.colo) || null, configured: Boolean(env.AUTH_TOKEN),
    };
    return new Response(JSON.stringify(body), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return new Response(DECOY, { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });
}

/** null means: this is the tunnel, upgrade it. Otherwise the Response to send. */
export function route(request, env) {
  const wantsWs = (request.headers.get("Upgrade") || "").toLowerCase() === "websocket";
  if (wantsWs && new URL(request.url).pathname === wsPathOf(env)) return null;
  return handleHttp(request, env);
}

export default {
  async fetch(request, env) {
    const response = route(request, env);
    if (response) return response;
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    attachSession(server, env, connect);
    return new Response(null, { status: 101, webSocket: client });
  },
};
