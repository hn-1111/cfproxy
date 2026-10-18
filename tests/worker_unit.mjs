// Unit tests of the pure functions of worker/index.js (run by tests/test_worker.py, or: node tests/worker_unit.mjs).
// The worker's one Workers-only import is pointed at a shim, exactly like edge_harness.mjs does.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(path.join(here, "..", "worker", "index.js"), "utf8");
const marker = 'import { connect } from "cloudflare:sockets";';
assert.ok(source.includes(marker), "worker/index.js no longer imports connect from cloudflare:sockets");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfp-unit-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
fs.writeFileSync(path.join(tmp, "sockets.mjs"), "export const connect = () => { throw new Error('no network in unit tests'); };\n");
fs.writeFileSync(path.join(tmp, "worker.mjs"), source.replace(marker, 'import { connect } from "./sockets.mjs";'));
const w = await import(pathToFileURL(path.join(tmp, "worker.mjs")));

let count = 0;
const test = async (name, fn) => {
  try { await fn(); } catch (e) { console.error(`FAILED: ${name}`); throw e; }
  count++;
};

const hex = (n) => "a".repeat(n);
const good = { v: 1, ts: 1700000000, sig: hex(64), host: "149.154.167.51", port: 443 };

await test("Telegram addresses are recognised", () => {
  for (const ip of ["149.154.167.51", "149.154.175.50", "149.154.175.100", "149.154.167.91", "149.154.171.5",
    "95.161.76.100", "91.108.56.130", "91.108.4.1", "91.108.23.255", "91.105.192.1", "91.105.193.255", "185.76.151.9"]) {
    assert.equal(w.isTelegramHost(ip), true, ip);
  }
  for (const v6 of ["2001:b28:f23d::1", "2001:B28:F23F:1::2", "2001:67c:4e8::5", "2a0a:f280:1::1"]) {
    assert.equal(w.isTelegramHost(v6), true, v6);
  }
});

await test("everything else is not Telegram", () => {
  for (const host of ["8.8.8.8", "1.1.1.1", "149.154.176.1", "149.154.159.255", "91.105.194.0", "91.108.24.1", "185.76.150.255",
    "telegram.org", "149.154.167.51.evil.example", "::ffff:149.154.167.51", "2001:db8::1", "999.1.1.1", "", "127.0.0.1"]) {
    assert.equal(w.isTelegramHost(host), false, host);
  }
});

await test("targetAllowed: all lets every port through, telegram only Telegram", () => {
  assert.equal(w.targetAllowed({}, "example.com", 80), true);
  assert.equal(w.targetAllowed({ ALLOW: "all" }, "10.0.0.1", 65535), true);
  assert.equal(w.targetAllowed({ ALLOW: "all" }, "example.com", 0), false);
  assert.equal(w.targetAllowed({ ALLOW: "all" }, "example.com", 65536), false);
  assert.equal(w.targetAllowed({ ALLOW: "telegram" }, "example.com", 443), false);
  assert.equal(w.targetAllowed({ ALLOW: "TELEGRAM" }, "149.154.167.51", 443), true);
});

await test("parseHello accepts a good hello", () => {
  assert.deepEqual(w.parseHello(JSON.stringify(good)), { ts: good.ts, port: 443, host: good.host, sig: good.sig });
  assert.ok(w.parseHello(JSON.stringify({ ...good, host: "example.com" })));
  assert.ok(w.parseHello(JSON.stringify({ ...good, host: "2001:db8::1" })));
});

await test("parseHello refuses everything else", () => {
  const bad = [
    "not json", "", "null", "[]", "42", JSON.stringify("text"),
    JSON.stringify({ ...good, port: 0 }), JSON.stringify({ ...good, port: 65536 }), JSON.stringify({ ...good, port: "443" }),
    JSON.stringify({ ...good, port: 443.5 }), JSON.stringify({ ...good, ts: "1700000000" }), JSON.stringify({ ...good, ts: 1.5 }),
    JSON.stringify({ ...good, host: "a b" }), JSON.stringify({ ...good, host: "a/b" }), JSON.stringify({ ...good, host: "" }),
    JSON.stringify({ ...good, host: "x".repeat(254) }), JSON.stringify({ ...good, host: 5 }),
    JSON.stringify({ ...good, sig: hex(63) }), JSON.stringify({ ...good, sig: "G".repeat(64) }), JSON.stringify({ ...good, sig: "A".repeat(64) }),
    JSON.stringify({ ...good, pad: "x".repeat(2000) }),
  ];
  for (const text of bad) assert.equal(w.parseHello(text), null, text.slice(0, 60));
  assert.equal(w.parseHello(new ArrayBuffer(8)), null); // a binary frame is not a hello
});

await test("the paths", () => {
  assert.equal(w.wsPathOf({}), "/ws");
  assert.equal(w.wsPathOf({ WS_PATH: "abc" }), "/abc");
  assert.equal(w.wsPathOf({ WS_PATH: " /abc/def " }), "/abc/def");
  assert.equal(w.healthPathOf({ WS_PATH: "/abc" }), "/abc/health");
  assert.equal(w.healthPathOf({ WS_PATH: "/abc/" }), "/abc/health");
  assert.equal(w.healthPathOf({}), "/ws/health");
});

const req = (url, headers = {}) => new Request(url, { headers });
const env = { WS_PATH: "/secret", AUTH_TOKEN: "t" };

await test("route: only a WebSocket upgrade on the secret path becomes a tunnel", () => {
  assert.equal(w.route(req("https://h.example/secret", { Upgrade: "websocket" }), env), null);
  assert.equal(w.route(req("https://h.example/secret", { Upgrade: "WebSocket" }), env), null);
  assert.notEqual(w.route(req("https://h.example/secret"), env), null);                                  // no upgrade
  assert.notEqual(w.route(req("https://h.example/other", { Upgrade: "websocket" }), env), null);         // wrong path
});

await test("route: the decoy page, the 404 and the probe under the secret path", async () => {
  const home = w.route(req("https://h.example/"), env);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /under construction/);
  for (const p of ["/health", "/secret", "/other", "/secret/other", "/ws/health", "/robots.txt"]) {
    assert.equal(w.route(req("https://h.example" + p), env).status, 404, p);
  }
  const probe = w.route(req("https://h.example/secret/health"), env);
  assert.equal(probe.status, 200);
  assert.equal(probe.headers.get("cache-control"), "no-store");
  const body = await probe.json();
  assert.deepEqual([body.ok, body.app, body.configured], [true, "cfproxy", true]);
  const open = await w.route(req("https://h.example/secret/health"), { WS_PATH: "/secret" }).json();
  assert.equal(open.configured, false);
});

await test("the health answer does not leak the secrets", async () => {
  const text = await w.route(req("https://h.example/secret/health"), env).text();
  assert.ok(!text.includes("secret") && !text.includes('"t"'), text);
});

await test("checkHello", async () => {
  const sign = async (token, ts, host, port) => {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(token), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${ts}|${host}|${port}`)));
    return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
  };
  const now = 1_700_000_000_000;
  const hello = { ts: 1_700_000_000, host: "149.154.167.51", port: 443, sig: await sign("token", 1_700_000_000, "149.154.167.51", 443) };
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, hello, now), "");
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, hello, now + 299_000), "");
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, hello, now + 301_000), "clock");
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, hello, now - 301_000), "clock");
  assert.equal(await w.checkHello({ AUTH_TOKEN: "other" }, hello, now), "auth");
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, { ...hello, port: 444 }, now), "auth");   // the target is signed
  assert.equal(await w.checkHello({ AUTH_TOKEN: "token" }, { ...hello, host: "8.8.8.8" }, now), "auth");
  assert.equal(await w.checkHello({}, hello, now), "not-configured");
});

console.log(`worker unit tests: ${count} passed`);
