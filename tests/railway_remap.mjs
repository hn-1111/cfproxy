// Test-only. Loaded with NODE_OPTIONS="--import <this file>" by the fake Railway: lets the tunnel exit "reach Telegram" in the
// test network by pointing chosen addresses at local servers.   CFP_TEST_REMAP="149.154.167.51:443=127.0.0.1:9000,..."
import net from "node:net";

const map = new Map();
for (const item of (process.env.CFP_TEST_REMAP || "").split(",").filter(Boolean)) {
  const [from, to] = item.split("=");
  map.set(from, to);
}
const connect = net.connect;
net.connect = function (...args) {
  const o = args[0];
  const to = o && typeof o === "object" ? map.get(`${o.host}:${o.port}`) : undefined;
  if (to) {
    const at = to.lastIndexOf(":");
    args[0] = { ...o, host: to.slice(0, at), port: Number(to.slice(at + 1)) };
  }
  return connect.apply(this, args);
};
