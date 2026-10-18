"""Settings, ports, the .env file, the proxy links and the endpoint store."""
import json
import os
import stat
import tempfile
import unittest
import urllib.parse
from unittest import mock

import helpers  # noqa: F401  (puts lib/ on the path)

import cfp_common as common
from cfp_common import ALL_PORTS, PLAIN_PORTS, TLS_PORTS, ConfigError, Settings


class Ports(unittest.TestCase):
    def test_the_thirteen_cloudflare_ports(self):
        self.assertEqual(TLS_PORTS, (443, 8443, 2053, 2083, 2087, 2096))
        self.assertEqual(PLAIN_PORTS, (80, 8080, 8880, 2052, 2082, 2086, 2095))
        self.assertEqual(ALL_PORTS, TLS_PORTS + PLAIN_PORTS)
        self.assertEqual(len(set(ALL_PORTS)), 13)

    def test_parse_ports(self):
        self.assertEqual(common.parse_ports(""), list(ALL_PORTS))
        self.assertEqual(common.parse_ports("all"), list(ALL_PORTS))
        self.assertEqual(common.parse_ports("tls"), list(TLS_PORTS))
        self.assertEqual(common.parse_ports("plain"), list(PLAIN_PORTS))
        self.assertEqual(common.parse_ports("443, 8443 2053"), [443, 8443, 2053])
        self.assertEqual(common.parse_ports("8080,tls,443"), [8080, 443, 8443, 2053, 2083, 2087, 2096])  # no duplicates
        self.assertEqual(common.parse_ports("TLS"), list(TLS_PORTS))

    def test_bad_ports(self):
        for bad in ("web", "0", "70000", "44a", "-1"):
            with self.assertRaises(ConfigError, msg=bad):
                common.parse_ports(bad)


class EnvFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfp-env-")
        self.path = os.path.join(self.dir, "sub", ".env")
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)

    def test_parse(self):
        text = '# comment\n\nA=1\nexport B="two words"\nC=\'x\'\n  D = spaced \nbad line\n1X=no\nE=a=b\n'
        self.assertEqual(common.parse_env_text(text),
                         {"A": "1", "B": "two words", "C": "x", "D": "spaced", "E": "a=b"})

    def test_set_creates_the_folder_and_keeps_the_file_private(self):
        with mock.patch.dict(os.environ):
            common.env_set(self.path, "TOKEN", "abc")
            self.assertEqual(os.environ["TOKEN"], "abc")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        with open(self.path) as f:
            self.assertEqual(f.read(), 'TOKEN="abc"\n')

    def test_set_replaces_the_first_assignment_and_drops_duplicates(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("# keep me\nA=1\nexport B=2\nA=3\nC=4\n")
        with mock.patch.dict(os.environ):
            common.env_set(self.path, "A", "new")
            common.env_set(self.path, "B", "newer")
            common.env_set(self.path, "Z", "last")
        with open(self.path) as f:
            self.assertEqual(f.read(), '# keep me\nA="new"\nB="newer"\nC=4\nZ="last"\n')

    def test_load_env_never_overrides_what_is_already_set(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("CFP_T_ONE=file\nCFP_T_TWO=file\n")
        with mock.patch.dict(os.environ, {"CFP_T_ONE": "shell"}):
            os.environ.pop("CFP_T_TWO", None)
            common.load_env(self.path)
            self.assertEqual((os.environ["CFP_T_ONE"], os.environ["CFP_T_TWO"]), ("shell", "file"))

    def test_a_missing_file_is_fine(self):
        self.assertEqual(common.load_env(os.path.join(self.dir, "nope")), {})


class SettingsTests(unittest.TestCase):
    def test_from_env(self):
        env = {"WORKER_HOST": "w.example.workers.dev", "WS_PATH": "abc", "AUTH_TOKEN": "t", "MTPROTO_SECRET": "AA" * 16,
               "SOCKS_USER": "u", "SOCKS_PASS": "p", "SOCKS_PORT": "1081", "MTPROTO_PORT": "1444"}
        with mock.patch.dict(os.environ, env):
            st = Settings.from_env()
        self.assertEqual((st.host, st.ws_path, st.auth_token), ("w.example.workers.dev", "/abc", "t"))
        self.assertEqual((st.mtproto_secret, st.socks_port, st.mtproto_port), ("aa" * 16, 1081, 1444))

    def test_the_custom_domain_is_the_host_when_there_is_no_worker_host(self):
        with mock.patch.dict(os.environ, {"CUSTOM_DOMAIN": "proxy.example.com"}):
            os.environ.pop("WORKER_HOST", None)
            self.assertEqual(Settings.from_env().host, "proxy.example.com")

    def test_a_bad_port_setting(self):
        with mock.patch.dict(os.environ, {"SOCKS_PORT": "http"}):
            with self.assertRaises(ConfigError):
                Settings.from_env()

    def test_require(self):
        st = Settings(host="h", auth_token="t", mtproto_secret="0" * 32)
        st.require("host", "auth_token", "mtproto_secret")
        with self.assertRaises(ConfigError) as caught:
            Settings().require("host")
        self.assertIn("WORKER_HOST", str(caught.exception))
        with self.assertRaises(ConfigError):
            Settings(mtproto_secret="xyz").require("mtproto_secret")
        with self.assertRaises(ConfigError):
            Settings(mtproto_secret="0" * 31).require("mtproto_secret")


class Links(unittest.TestCase):
    SECRET = "00112233445566778899aabbccddeeff"

    def test_mtproto(self):
        links = common.mtproto_links("127.0.0.1", 1443, self.SECRET)
        self.assertEqual(links, [f"tg://proxy?server=127.0.0.1&port=1443&secret=dd{self.SECRET}",
                                 f"https://t.me/proxy?server=127.0.0.1&port=1443&secret=dd{self.SECRET}"])

    def test_socks_with_a_login(self):
        links = common.socks_links("192.168.1.5", 1080, "bob", "p@ss w/rd")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(links[0]).query)
        self.assertEqual((query["server"], query["port"], query["user"], query["pass"]),
                         (["192.168.1.5"], ["1080"], ["bob"], ["p@ss w/rd"]))
        self.assertEqual(links[2], "socks5://bob:p%40ss%20w%2Frd@192.168.1.5:1080")

    def test_socks_without_a_login(self):
        links = common.socks_links("127.0.0.1", 1080)
        self.assertEqual(links, ["tg://socks?server=127.0.0.1&port=1080", "https://t.me/socks?server=127.0.0.1&port=1080",
                                 "socks5://127.0.0.1:1080"])


class EndpointStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfp-store-")
        self.path = os.path.join(self.dir, "a", "endpoints.json")
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)

    def test_round_trip(self):
        eps = [{"ip": "104.16.1.2", "port": 443, "tls": True, "ms": 40.0, "tunnel_ms": 200.0, "colo": "FRA"}]
        common.save_endpoints(eps, {"host": "w.workers.dev", "ports": [443]}, self.path)
        got, meta = common.load_endpoints(self.path)
        self.assertEqual(got, eps)
        self.assertEqual((meta["host"], meta["version"]), ("w.workers.dev", 1))
        self.assertIn("scanned_at", meta)

    def test_no_file_and_no_endpoint_are_config_errors(self):
        with self.assertRaises(ConfigError) as caught:
            common.load_endpoints(self.path)
        self.assertIn("scan", str(caught.exception))
        common.save_endpoints([], {}, self.path)
        with self.assertRaises(ConfigError):
            common.load_endpoints(self.path)
        with open(self.path, "w") as f:
            f.write("{broken")
        with self.assertRaises(ConfigError):
            common.load_endpoints(self.path)

    def test_rows_without_ip_or_port_are_ignored(self):
        common.save_endpoints([{"ip": "1.1.1.1"}, {"port": 443}, {"ip": "2.2.2.2", "port": 80}], {}, self.path)
        self.assertEqual([e["ip"] for e in common.load_endpoints(self.path)[0]], ["2.2.2.2"])

    def test_the_saved_file_is_plain_json(self):
        common.save_endpoints([{"ip": "1.1.1.1", "port": 443}], {}, self.path)
        with open(self.path) as f:
            self.assertEqual(json.load(f)["endpoints"][0]["ip"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
