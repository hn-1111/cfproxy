/**
 * cfproxy - the tunnel exit for Railway (or any machine with Node 18+): the Worker's protocol on an ordinary server.
 *
 * The protocol, the checks and the session logic are NOT written a second time here. The deploy script
 * (lib/cfp_deploy.py, railway_app) pastes the real worker/index.js into this file at the marker below, so both exits
 * behave the same. What this file adds is what Cloudflare gives a Worker for free and a server must do itself:
 *   - a WebSocket server (RFC 6455) in front of attachSession(), and the plain HTTP side (decoy page, health probe),
 *   - outbound TCP with net.connect(), with back-pressure in both directions (a slow phone must not fill the memory),
 *   - a refusal to open connections into private networks (this machine's, Railway's private network, metadata, ...).
 *
 * Settings (environment variables; on Railway: the service variables):
 *   AUTH_TOKEN  required, the shared secret          WS_PATH  path of the tunnel endpoint, default /ws
 *   ALLOW       "all" (default) or "telegram"        PORT     the port to listen on (Railway sets it), default 8080
 *   HOST        address to listen on (default: every interface)
 *   CFP_ALLOW_PRIVATE=1  lets tunnels reach private addresses. For the tests only: never set it on a server.
 *   CFP_HELLO_TIMEOUT_MS  how long a connection may stay silent before it is dropped (default 10000; the tests shorten it)
 *
 * Standard library only. Run:  AUTH_TOKEN=... node <the assembled file>
 */
import dnsPromises from "node:dns/promises";
import http from "node:http";
import net from "node:net";
import nodeCrypto from "node:crypto";

//@@WORKER@@

// ===================================================================== the Node side
const settings = process.env;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HELLO_BYTES = 2048; // until the hello arrived, nothing bigger than this is read from a stranger
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
const HELLO_TIMEOUT_MS = Number(settings.CFP_HELLO_TIMEOUT_MS) || 10000; // a connection that says nothing is dropped
const CONNECT_TIMEOUT_MS = 10000;
const CLOSE_GRACE_MS = 2000;

// ---------------------------------------------------------------- no tunnels into private networks
function privateV4(ip) {
  const [a, b, c] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127) // carrier-grade NAT
    || (a === 169 && b === 254) // link-local, cloud metadata
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0 && c === 0)
    || (a === 198 && (b === 18 || b === 19));
}

function privateAddress(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) return privateV4(ip);
  if (kind === 6) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return privateV4(mapped[1]);
    const first = parseInt(lower.split(":")[0] || "0", 16);
    return !(first >= 0x2000 && first <= 0x3fff); // only global unicast (2000::/3) is let through
  }
  return true;
}

/** The address to connect to, looked up once and checked: the connection then goes to exactly that address. */
async function resolveTarget(host) {
  const allowPrivate = settings.CFP_ALLOW_PRIVATE === "1";
  if (net.isIP(host)) {
    if (!allowPrivate && privateAddress(host)) throw new Error("blocked address");
    return host;
  }
  const lower = host.toLowerCase();
  if (!allowPrivate && (lower === "localhost" || /\.(localhost|local|internal)$/.test(lower))) throw new Error("blocked address");
  const found = await dnsPromises.lookup(host, { all: true });
  if (!found.length) throw new Error("no address");
  if (!allowPrivate && found.some((f) => privateAddress(f.address))) throw new Error("blocked address");
  return (found.find((f) => f.family === 4) || found[0]).address;
}

// ---------------------------------------------------------------- outbound TCP, shaped like cloudflare:sockets connect()
/**
 * What attachSession() expects from a socket: { opened, readable.getReader().read(), writable.getWriter().write(), close() }.
 * Reading happens only when the relay asks for more AND the WebSocket side is not backed up; writing to the target
 * pauses the WebSocket input until the target has taken the data. That is the whole back-pressure.
 */
function openTcp(address, ws) {
  let sock = null;
  let closed = false;
  let pending = null; // a chunk read from the target that the relay has not taken yet
  let ended = false;
  let failure = null;
  let wake = null;
  const poke = () => { const w = wake; wake = null; if (w) w(); };

  const opened = (async () => {
    const ip = await resolveTarget(address.hostname);
    if (closed) throw new Error("closed");
    await new Promise((resolve, reject) => {
      sock = net.connect({ host: ip, port: address.port });
      sock.setNoDelay(true);
      sock.setTimeout(CONNECT_TIMEOUT_MS);
      sock.on("error", (e) => { failure = e; poke(); reject(e); }); // after the connect, reject() does nothing
      sock.on("data", (chunk) => { pending = pending ? Buffer.concat([pending, chunk]) : chunk; sock.pause(); poke(); });
      sock.on("end", () => { ended = true; poke(); });
      sock.on("close", () => { ended = true; poke(); });
      sock.once("timeout", () => sock.destroy(new Error("timed out")));
      sock.once("connect", () => { sock.setTimeout(0); sock.setKeepAlive(true, 30000); resolve(); });
    });
    if (closed) { sock.destroy(); throw new Error("closed"); }
    sock.pause();
  })();
  opened.catch(() => {});

  const reader = {
    async read() {
      await opened;
      await ws.drained();
      for (;;) {
        if (pending) { const value = pending; pending = null; return { value, done: false }; }
        if (failure) throw failure;
        if (ended) return { value: undefined, done: true };
        await new Promise((resolve) => { wake = resolve; sock.resume(); });
      }
    },
  };

  const writer = {
    async write(bytes) {
      await opened;
      if (closed || sock.destroyed) throw new Error("connection closed");
      if (sock.write(bytes)) return;
      ws.pauseInput();
      try {
        await new Promise((resolve, reject) => {
          const off = () => { sock.off("drain", done); sock.off("close", broken); };
          const done = () => { off(); resolve(); };
          const broken = () => { off(); reject(new Error("connection closed")); };
          sock.once("drain", done);
          sock.once("close", broken);
        });
      } finally {
        ws.resumeInput();
      }
    },
  };

  return {
    opened,
    readable: { getReader: () => reader },
    writable: { getWriter: () => writer },
    close() { closed = true; if (sock) sock.destroy(); poke(); return Promise.resolve(); },
  };
}

// ---------------------------------------------------------------- the WebSocket, shaped like the Worker's
/** A server-side WebSocket (RFC 6455) with the surface attachSession() uses: addEventListener, send, close. */
class NodeWebSocket {
  constructor(socket, head) {
    this.socket = socket;
    this.handlers = { message: [], close: [], error: [] };
    this.buffer = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
    this.limit = MAX_HELLO_BYTES;
    this.chunks = [];
    this.size = 0;
    this.kind = 0;
    this.sent = false; // our close frame went out
    this.over = false; // the socket is gone and "close" was announced
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30000);
    socket.on("data", (d) => { this.buffer = this.buffer.length ? Buffer.concat([this.buffer, d]) : d; this.parse(); });
    socket.on("error", () => this.emit("error", {}));
    socket.on("close", () => { clearTimeout(this.timer); if (!this.over) { this.over = true; this.emit("close", {}); } });
    this.timer = setTimeout(() => this.close(1008, "no hello"), HELLO_TIMEOUT_MS);
    this.timer.unref();
    if (this.buffer.length) this.parse();
  }

  addEventListener(type, fn) { this.handlers[type].push(fn); }

  emit(type, event) {
    for (const fn of this.handlers[type]) {
      try { fn(event); } catch { this.close(1011, "relay error"); }
    }
  }

  header(opcode, n) {
    if (n < 126) return Buffer.from([0x80 | opcode, n]);
    if (n < 65536) return Buffer.from([0x80 | opcode, 126, n >> 8, n & 255]);
    const h = Buffer.alloc(10);
    h[0] = 0x80 | opcode;
    h[1] = 127;
    h.writeBigUInt64BE(BigInt(n), 2);
    return h;
  }

  send(data) {
    if (this.sent || this.socket.destroyed) throw new Error("socket closed");
    const text = typeof data === "string";
    const payload = text ? Buffer.from(data, "utf8")
      : data instanceof ArrayBuffer ? Buffer.from(data) : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    this.socket.cork();
    this.socket.write(this.header(text ? 1 : 2, payload.length));
    this.socket.write(payload);
    this.socket.uncork();
  }

  close(code = 1000, reason = "") {
    if (this.sent) return;
    this.sent = true;
    clearTimeout(this.timer);
    if (this.socket.destroyed) return;
    const text = Buffer.from(String(reason).slice(0, 100));
    const body = Buffer.alloc(2 + text.length);
    body.writeUInt16BE(code, 0);
    text.copy(body, 2);
    this.socket.end(Buffer.concat([this.header(8, body.length), body]));
    setTimeout(() => this.socket.destroy(), CLOSE_GRACE_MS).unref();
  }

  /** true while the socket cannot take more data: the relay then stops reading from the target */
  drained() {
    const s = this.socket;
    if (!s.writableNeedDrain || s.destroyed) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => { s.off("drain", done); s.off("close", done); resolve(); };
      s.once("drain", done);
      s.once("close", done);
    });
  }

  pauseInput() { this.socket.pause(); }

  resumeInput() { if (!this.socket.destroyed) this.socket.resume(); }

  parse() {
    for (;;) {
      if (this.sent || this.buffer.length < 2) return;
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const op = b0 & 0x0f;
      let n = b1 & 0x7f;
      let at = 2;
      if ((b0 & 0x70) !== 0 || (b1 & 0x80) === 0) return this.close(1002, "protocol error"); // reserved bits / unmasked
      if (n === 126) {
        if (this.buffer.length < 4) return;
        n = this.buffer.readUInt16BE(2);
        at = 4;
      } else if (n === 127) {
        if (this.buffer.length < 10) return;
        const big = this.buffer.readBigUInt64BE(2);
        if (big > BigInt(MAX_MESSAGE_BYTES)) return this.close(1009, "too big");
        n = Number(big);
        at = 10;
      }
      if (op >= 8 && (n > 125 || !fin)) return this.close(1002, "protocol error");
      if (op < 8 && this.size + n > this.limit) return this.close(1009, "too big");
      const end = at + 4 + n;
      if (this.buffer.length < end) return;
      const key = this.buffer.subarray(at, at + 4);
      const payload = Buffer.from(this.buffer.subarray(at + 4, end));
      for (let i = 0; i < payload.length; i++) payload[i] ^= key[i & 3];
      this.buffer = this.buffer.subarray(end);

      if (op === 9) { // ping
        if (!this.socket.destroyed) this.socket.write(Buffer.concat([this.header(10, payload.length), payload]));
      } else if (op === 8) { // close: answer in kind
        this.close(payload.length >= 2 ? payload.readUInt16BE(0) : 1000, "");
        return;
      } else if (op === 1 || op === 2 || op === 0) {
        if (op === 0 ? this.kind === 0 : this.kind !== 0) return this.close(1002, "protocol error");
        if (op !== 0) this.kind = op;
        this.chunks.push(payload);
        this.size += payload.length;
        if (fin) {
          const whole = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks);
          const data = this.kind === 1 ? whole.toString("utf8") : whole;
          this.chunks = [];
          this.size = 0;
          this.kind = 0;
          if (this.limit === MAX_HELLO_BYTES) { this.limit = MAX_MESSAGE_BYTES; clearTimeout(this.timer); }
          this.emit("message", { data });
        }
      } // op 10 (pong) and anything else: nothing to do
    }
  }
}

// ---------------------------------------------------------------- the HTTP server
function requestOf(req) {
  const request = new Request(`http://${req.headers.host || "localhost"}${req.url}`, { headers: req.headers });
  request.cf = { colo: settings.RAILWAY_REPLICA_REGION || settings.RAILWAY_REGION || null };
  return request;
}

const live = new Set();

const server = http.createServer(async (req, res) => {
  try {
    const response = route(requestOf(req), settings) || new Response("Upgrade Required", { status: 426 });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    if (!res.headersSent) res.writeHead(400, { "content-type": "text/plain" });
    res.end("Bad request");
  }
});
// Railway's proxy keeps connections to us for 60 s: ours must live longer, or its next request meets a closed socket
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

server.on("upgrade", (req, socket, head) => {
  socket.on("error", () => {});
  let request = null;
  try { request = requestOf(req); } catch { /* answered below */ }
  const key = String(req.headers["sec-websocket-key"] || "");
  if (!request || route(request, settings) !== null) {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  if (req.headers["sec-websocket-version"] !== "13" || !/^[A-Za-z0-9+/]{22}==$/.test(key)) {
    socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  const accept = nodeCrypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  live.add(socket);
  socket.on("close", () => live.delete(socket));
  const ws = new NodeWebSocket(socket, head);
  attachSession(ws, settings, (address) => openTcp(address, ws));
});

function shutdown() {
  server.close();
  for (const socket of live) socket.destroy();
  setTimeout(() => process.exit(0), 300).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("uncaughtException", (e) => console.error(`cfproxy: unexpected error: ${e && e.message}`));
process.on("unhandledRejection", (e) => console.error(`cfproxy: unexpected error: ${e && e.message}`));

const port = Number(settings.PORT) || 8080;
server.listen(port, settings.HOST || undefined, () => {
  const a = server.address();
  console.log(`cfproxy exit ${VERSION}: listening on ${typeof a === "object" && a ? a.port : port}, ALLOW=${String(settings.ALLOW || "all")}, `
    + (settings.AUTH_TOKEN ? "configured" : "NO AUTH_TOKEN: every tunnel is refused"));
});
