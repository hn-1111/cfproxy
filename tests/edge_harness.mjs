// A stand-in for the Cloudflare edge, for the tests only. It runs the REAL worker/index.js (route, handleHttp,
// attachSession) behind a plain HTTP/WebSocket server (and a TLS one when a key is given). The only things that
// differ from Cloudflare are the three Workers-only pieces: cloudflare:sockets connect() (here: net.connect, with an
// optional address map so a "Telegram" address can land on a local fake), WebSocketPair and the 101 Response.
//
//   node edge_harness.mjs --auth TOKEN [--ws-path /ws] [--allow all|telegram] [--map 1.2.3.4:443=127.0.0.1:9000]
//                         [--tls-key k.pem --tls-cert c.pem]
// Prints one line, READY {"plain":PORT,"tls":PORT|null}, and serves until it is killed.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
const env = { AUTH_TOKEN: args.auth || "", WS_PATH: args["ws-path"] || "/ws", ALLOW: args.allow || "all" };
const remap = new Map();
for (const item of (args.map || "").split(",").filter(Boolean)) {
  const [from, to] = item.split("=");
  remap.set(from, to);
}

// load the real worker, with its one Workers-only import pointed at a shim
const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(path.join(here, "..", "worker", "index.js"), "utf8");
const marker = 'import { connect } from "cloudflare:sockets";';
if (!source.includes(marker)) throw new Error("worker/index.js no longer imports connect from cloudflare:sockets");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfp-edge-"));
fs.writeFileSync(path.join(tmp, "sockets.mjs"), "export const connect = (...a) => globalThis.__connect(...a);\n");
fs.writeFileSync(path.join(tmp, "worker.mjs"), source.replace(marker, 'import { connect } from "./sockets.mjs";'));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => process.exit(0));

globalThis.__connect = (address) => {
  let { hostname, port } = address;
  const to = remap.get(`${hostname}:${port}`);
  if (to) {
    const i = to.lastIndexOf(":");
    hostname = to.slice(0, i);
    port = Number(to.slice(i + 1));
  }
  const sock = net.connect({ host: hostname, port });
  sock.on("error", () => {});
  const opened = new Promise((resolve, reject) => {
    sock.once("connect", () => resolve({}));
    sock.once("error", reject);
  });
  opened.catch(() => {});
  return {
    opened,
    readable: Readable.toWeb(sock),
    writable: Writable.toWeb(sock),
    close: () => { sock.destroy(); return Promise.resolve(); },
  };
};
const worker = await import(pathToFileURL(path.join(tmp, "worker.mjs")));

// ---- a minimal server-side WebSocket with the same surface Workers gives the Worker
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

class FakeWebSocket {
  constructor(socket, head) {
    this.socket = socket;
    this.handlers = { message: [], close: [], error: [] };
    this.buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
    this.closed = false;
    this.fragments = [];
    socket.on("data", (d) => { this.buf = Buffer.concat([this.buf, d]); this.parse(); });
    socket.on("close", () => this.emit("close", {}));
    socket.on("error", () => this.emit("error", {}));
    if (this.buf.length) this.parse();
  }
  addEventListener(type, fn) { this.handlers[type].push(fn); }
  emit(type, ev) { for (const fn of this.handlers[type]) fn(ev); }
  frame(opcode, payload) {
    const n = payload.length;
    const head = n < 126 ? Buffer.from([0x80 | opcode, n])
      : n < 65536 ? Buffer.from([0x80 | opcode, 126, n >> 8, n & 255])
        : (() => { const b = Buffer.alloc(10); b[0] = 0x80 | opcode; b[1] = 127; b.writeBigUInt64BE(BigInt(n), 2); return b; })();
    return Buffer.concat([head, payload]);
  }
  send(data) {
    if (this.closed) throw new Error("socket closed");
    const text = typeof data === "string";
    const payload = text ? Buffer.from(data) : Buffer.from(data.buffer ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : data);
    this.socket.write(this.frame(text ? 1 : 2, payload));
  }
  close(code = 1000) {
    if (this.closed) return;
    this.closed = true;
    const p = Buffer.alloc(2);
    p.writeUInt16BE(code);
    this.socket.end(this.frame(8, p));
  }
  parse() {
    for (;;) {
      if (this.buf.length < 2) return;
      const fin = (this.buf[0] & 0x80) !== 0, op = this.buf[0] & 15, masked = (this.buf[1] & 0x80) !== 0;
      let n = this.buf[1] & 0x7f, off = 2;
      if (n === 126) { if (this.buf.length < 4) return; n = this.buf.readUInt16BE(2); off = 4; }
      else if (n === 127) { if (this.buf.length < 10) return; n = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      const need = off + (masked ? 4 : 0) + n;
      if (this.buf.length < need) return;
      const key = masked ? this.buf.subarray(off, off + 4) : null;
      const payload = Buffer.from(this.buf.subarray(off + (masked ? 4 : 0), need));
      if (key) for (let i = 0; i < payload.length; i++) payload[i] ^= key[i & 3];
      this.buf = this.buf.subarray(need);
      if (op === 9) this.socket.write(this.frame(10, payload));
      else if (op === 8) { this.close(); this.emit("close", {}); }
      else if (op === 1 || op === 2 || op === 0) {
        if (op !== 0) this.first = op;
        this.fragments.push(payload);
        if (fin) {
          const whole = Buffer.concat(this.fragments);
          this.fragments = [];
          const data = this.first === 1 ? whole.toString("utf8")
            : whole.buffer.slice(whole.byteOffset, whole.byteOffset + whole.length);
          this.emit("message", { data });
        }
      }
    }
  }
}

function attach(server, scheme) {
  server.on("request", async (req, res) => {
    const request = new Request(`${scheme}://${req.headers.host}${req.url}`, { headers: req.headers });
    const response = worker.route(request, env) || new Response("upgrade required", { status: 426 });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  });
  server.on("upgrade", (req, socket, head) => {
    const request = new Request(`${scheme}://${req.headers.host}${req.url}`, { headers: req.headers });
    if (worker.route(request, env) !== null) { socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"); return; }
    const accept = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + GUID).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    worker.attachSession(new FakeWebSocket(socket, head), env, globalThis.__connect);
  });
}

const plain = http.createServer();
attach(plain, "http");
await new Promise((r) => plain.listen(Number(args.port || 0), "0.0.0.0", r));
let tlsPort = null;
if (args["tls-key"] && args["tls-cert"]) {
  const secure = https.createServer({ key: fs.readFileSync(args["tls-key"]), cert: fs.readFileSync(args["tls-cert"]) });
  attach(secure, "https");
  await new Promise((r) => secure.listen(0, "0.0.0.0", r));
  tlsPort = secure.address().port;
}
console.log(`READY ${JSON.stringify({ plain: plain.address().port, tls: tlsPort })}`);
