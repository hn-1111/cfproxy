"""The scanner: probes, the full scan against the real Worker code, and the helpers around it."""
import asyncio
import ipaddress
import random
import socket
import unittest

import helpers
from helpers import NEED_EDGE, fixtures, settings

import cfp_scan as scan
from cfp_common import CF_RANGES_V4, TLS_PORTS
from cfp_tunnel import TunnelRefused


def dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(NEED_EDGE, "needs node and openssl")
class AgainstTheWorker(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()

    def st(self, **kw):
        return settings(ssl_context=self.fx.tls_context, **kw)

    async def test_a_good_edge_answers_on_plain_and_tls_ports(self):
        for port, tls in ((self.fx.edge.plain, False), (self.fx.edge.tls, True)):
            result = await scan.probe_pair("127.0.0.1", port, tls, self.st(), 5)
            self.assertTrue(result["ok"], result)
            self.assertGreater(result["ms"], 0)

    async def test_the_probe_lives_under_the_secret_path(self):
        wrong = self.st(ws_path="/somewhere-else")
        result = await scan.probe_pair("127.0.0.1", self.fx.edge.plain, False, wrong, 5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "HTTP 404")  # the decoy site answers anywhere but the secret path

    async def test_a_certificate_for_another_name_is_refused(self):
        result = await scan.probe_pair("127.0.0.1", self.fx.edge.tls, True, self.st(host="other.test"), 5)
        self.assertFalse(result["ok"])
        self.assertIn("SSL", result["error"])

    async def test_a_closed_port(self):
        result = await scan.probe_pair("127.0.0.1", dead_port(), False, self.st(), 3)
        self.assertFalse(result["ok"])

    async def test_a_web_server_that_is_not_the_worker(self):
        async def handler(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        port = server.sockets[0].getsockname()[1]
        result = await scan.probe_pair("127.0.0.1", port, False, self.st(), 3)
        self.assertEqual((result["ok"], result["error"]), (False, "not the Worker"))

    async def test_a_full_scan_finds_and_proves_the_working_endpoints(self):
        plans = [(self.fx.edge.plain, False), (self.fx.edge.tls, True), (dead_port(), False)]
        seen = []
        endpoints, meta = await scan.scan(self.st(), ["127.0.0.1"], plans, timeout=3,
                                          progress=lambda *a: seen.append(a))
        self.assertEqual(len(endpoints), 2)
        self.assertEqual({e["port"] for e in endpoints}, {self.fx.edge.plain, self.fx.edge.tls})
        self.assertEqual([e["tls"] for e in endpoints if e["port"] == self.fx.edge.tls], [True])
        self.assertTrue(all(e["tunnel_ms"] > 0 for e in endpoints))
        self.assertEqual([e["tunnel_ms"] for e in endpoints], sorted(e["tunnel_ms"] for e in endpoints))
        self.assertEqual((meta["answered"], meta["verified"], meta["tunnel_ok"]), (2, True, 2))
        self.assertTrue({"probe", "verify"} <= {a[0] for a in seen})

    async def test_without_the_tunnel_step_only_the_probe_runs(self):
        endpoints, meta = await scan.scan(self.st(), ["127.0.0.1"], [(self.fx.edge.plain, False)], timeout=3,
                                          tunnel=False)
        self.assertEqual(len(endpoints), 1)
        self.assertNotIn("tunnel_ms", endpoints[0])
        self.assertFalse(meta["verified"])

    async def test_a_wrong_token_stops_the_scan_with_the_workers_answer(self):
        with self.assertRaises(TunnelRefused) as caught:
            await scan.scan(self.st(auth_token="not-the-token"), ["127.0.0.1"], [(self.fx.edge.plain, False)], timeout=3)
        self.assertEqual(caught.exception.code, "auth")

    async def test_nothing_answers(self):
        endpoints, meta = await scan.scan(self.st(), ["127.0.0.1"], [(dead_port(), False)], timeout=2)
        self.assertEqual((endpoints, meta["answered"]), ([], 0))


class Helpers(unittest.TestCase):
    def test_sample_ips_spread_over_different_blocks_inside_the_ranges(self):
        ips = scan.sample_ips(CF_RANGES_V4, 100, random.Random(7))
        self.assertEqual(len(ips), 100)
        nets = [ipaddress.ip_network(r) for r in CF_RANGES_V4]
        for ip in ips:
            self.assertTrue(any(ipaddress.ip_address(ip) in n for n in nets), ip)
        self.assertEqual(len({ip.rsplit(".", 1)[0] for ip in ips}), 100)  # one per /24

    def test_sample_ips_keeps_a_users_own_list(self):
        self.assertEqual(sorted(scan.sample_ips(["1.2.3.4", "5.6.7.8", "10.0.0.0/30", "bogus", "::1"], 2)),
                         ["1.2.3.4", "10.0.0.1", "10.0.0.2", "5.6.7.8"])

    def test_parse_ip_text(self):
        text = "1.1.1.1, 2.2.2.2  # two\n\n# nothing\n3.3.3.0/24\n"
        self.assertEqual(scan.parse_ip_text(text), ["1.1.1.1", "2.2.2.2", "3.3.3.0/24"])

    def test_port_plans_use_tls_on_the_https_ports_only(self):
        plans = dict(scan.port_plans([443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095]))
        self.assertEqual({p for p, tls in plans.items() if tls}, set(TLS_PORTS))
        self.assertEqual(len(plans), 13)

    def test_shortlist_spreads_over_ips_before_repeating_one(self):
        alive = sorted([
            {"ip": "A", "port": 443, "ms": 10}, {"ip": "A", "port": 8443, "ms": 11}, {"ip": "A", "port": 80, "ms": 12},
            {"ip": "B", "port": 443, "ms": 20}, {"ip": "C", "port": 443, "ms": 30}, {"ip": "B", "port": 80, "ms": 40},
        ], key=lambda r: r["ms"])
        picked = scan.shortlist(alive, 4)
        self.assertEqual([(r["ip"], r["port"]) for r in picked], [("A", 443), ("B", 443), ("C", 443), ("A", 8443)])
        self.assertEqual(len(scan.shortlist(alive, 100)), 6)

    def test_parse_response(self):
        self.assertIsNone(scan.parse_response(b"HTTP/1.1 200 OK\r\nA: b\r\n"))
        status, headers, body = scan.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCF-Ray: x-FRA\r\n\r\nhi")
        self.assertEqual((status, headers["cf-ray"], body), (200, "x-FRA", b"hi"))
        self.assertEqual(scan.parse_response(b"garbage\r\n\r\n")[0], 0)

    def test_dechunk(self):
        self.assertEqual(scan.dechunk(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"), b"hello world")
        self.assertEqual(scan.dechunk(b"zz\r\nbroken"), b"")

    def test_the_text_output(self):
        endpoints = [{"ip": "104.16.1.2", "port": 443, "tls": True, "ms": 41.2, "tunnel_ms": 230.0, "colo": "FRA"},
                     {"ip": "172.64.9.9", "port": 8080, "tls": False, "ms": 55.0, "colo": ""}]
        table = "\n".join(scan.format_table(endpoints))
        self.assertIn("104.16.1.2", table)
        self.assertIn("230 ms", table)
        self.assertEqual(scan.endpoint_lines(endpoints), "104.16.1.2:443\n172.64.9.9:8080\n")


if __name__ == "__main__":
    unittest.main()
