"""The whole chain, driven through the command line (lib/cfproxy.py):

  setup -> init -> deploy (fake GitHub runs the REAL workflow + cfp_deploy.py, fake wrangler / Cloudflare API)
        -> scan -> test -> serve (a real bridge process: SOCKS5 and MTProto through the REAL Worker code) -> destroy
"""
import asyncio
import base64
import contextlib
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import helpers
from helpers import HAVE_NODE, ROOT, SECRET_HEX, TOKEN, WS_PATH, fixtures

import cfp_common as common
import cfp_crypto as crypto
import cfp_gh as gh
import cfproxy
import cfp_mtproto as mt
import fakes
from test_bridge import socks_open

try:
    import yaml
except ImportError:
    yaml = None

ACCOUNT = "b" * 32
CF_TOKEN = "cf-chain-token"


@unittest.skipUnless(HAVE_NODE and yaml is not None, "needs node and PyYAML")
class Chain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()
        cls.plain = cls.fx.edge.plain

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cfp-home-")
        self.bin = tempfile.mkdtemp(prefix="cfp-bin-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.addCleanup(shutil.rmtree, self.bin, True)
        self.world = fakes.GitHubWorld()
        server, github_url = fakes.start_github(self.world)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.cf = fakes.FakeCloudflare(token=CF_TOKEN, account=ACCOUNT).start()
        self.addCleanup(self.cf.stop)
        self.calls_log = fakes.install_fake_npx(self.bin)
        self.world.runner_env = {
            "PATH": self.bin + os.pathsep + os.environ["PATH"], "CF_API_BASE": self.cf.url,
            "CFP_VERIFY_URL": f"http://127.0.0.1:{self.plain}{WS_PATH}/health",
            "FAKE_WRANGLER_LOG": self.calls_log, "FAKE_SUBDOMAIN": "acme"}
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in list(os.environ):
            if name.startswith(("CFP_", "CFPROXY_")) or name in (
                    "GITHUB_API_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "CF_API_TOKEN",
                    "CF_ACCOUNT_ID", "WORKER_HOST", "WORKER_NAME", "CUSTOM_DOMAIN", "ALLOW", "AUTH_TOKEN", "WS_PATH",
                    "MTPROTO_SECRET", "SOCKS_USER", "SOCKS_PASS", "PUBLIC_HOST"):
                del os.environ[name]
        os.environ.update({"CFPROXY_HOME": self.home, "GITHUB_API_BASE": github_url, "CFP_GH_POLL_SECONDS": "0.05",
                           "CFP_GH_RETRY_SECONDS": "0", "CFP_GH_START_TIMEOUT": "20", "NO_COLOR": "1"})
        # the Worker behind the local edge was started with these two: the .env of this test must hold the same
        env_file = common.env_file()
        common.env_set(env_file, "AUTH_TOKEN", TOKEN)
        common.env_set(env_file, "WS_PATH", WS_PATH)
        common.env_set(env_file, "MTPROTO_SECRET", SECRET_HEX)

    # ------------------------------------------------------------ helpers
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cfproxy.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setup_settings(self, **overrides):
        values = {"--github-token": self.world.token, "--repo": "alice/cfproxy", "--cf-token": CF_TOKEN,
                  "--cf-account": ACCOUNT, "--target": "worker", "--allow": "all"}
        values.update(overrides)
        argv = ["setup", "--non-interactive"] + [x for pair in values.items() for x in pair]
        code, _, err = self.cli(*argv)
        self.assertEqual(code, 0, err)

    def dotenv(self):
        with open(common.env_file(), encoding="utf-8") as f:
            return common.parse_env_text(f.read())

    def prepared(self):
        self.setup_settings()
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)

    def deployed(self):
        self.prepared()
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 0, err)

    def scanned(self, ports=None):
        ips = os.path.join(self.home, "ips.txt")
        with open(ips, "w") as f:
            f.write("127.0.0.1\n")
        code, _, err = self.cli("scan", "--ips", ips, "--ports", str(ports or self.plain), "--timeout", "3")
        self.assertEqual(code, 0, err)

    # ------------------------------------------------------------ setup
    def test_setup_writes_the_settings_and_makes_the_secrets_once(self):
        self.setup_settings()
        first = self.dotenv()
        self.assertEqual((first["GITHUB_REPO"], first["CF_ACCOUNT_ID"], first["CFP_TARGET"]), ("alice/cfproxy", ACCOUNT, "worker"))
        self.assertRegex(first["WORKER_NAME"], r"^cfproxy-[0-9a-f]{6}$")
        self.assertRegex(first["SOCKS_USER"], r"^u[0-9a-f]{6}$")
        self.assertEqual(len(first["CFPROXY_KEY"]), 44)  # base64 of 32 bytes
        self.assertEqual(os.stat(common.env_file()).st_mode & 0o777, 0o600)
        self.setup_settings()  # again: nothing is regenerated
        self.assertEqual(self.dotenv(), first)

    def test_setup_rejects_bad_values(self):
        for flag, value, word in (("--repo", "no-slash", "owner/name"), ("--cf-account", "123", "32 hex"),
                                  ("--target", "lambda", "worker, pages"), ("--allow", "web", "all, telegram"),
                                  ("--domain", "not a host", "hostname")):
            argv = ["setup", "--non-interactive", "--github-token", "x", "--repo", "alice/cfproxy", "--cf-token", "x",
                    "--cf-account", ACCOUNT, flag, value]
            code, _, err = self.cli(*argv)
            self.assertEqual(code, 2, flag)
            self.assertIn(word, err, flag)

    # ------------------------------------------------------------ init
    def test_init_creates_a_private_repository_and_sends_everything_the_runner_needs(self):
        self.setup_settings()
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)
        w = self.world
        self.assertTrue(w.private)
        self.assertEqual(set(w.files), set(gh.DEPLOY_FILES))
        for rel in gh.DEPLOY_FILES:
            with open(os.path.join(ROOT, *rel.split("/")), "rb") as f:
                self.assertEqual(w.files[rel], f.read(), rel)
        env = self.dotenv()
        self.assertEqual(w.secrets, {"CF_API_TOKEN": CF_TOKEN, "CF_ACCOUNT_ID": ACCOUNT, "AUTH_TOKEN": TOKEN, "WS_PATH": WS_PATH})
        self.assertEqual(set(w.vars), {"WORKER_NAME", "ALLOW", "CFP_PUBKEY"})
        self.assertEqual(w.vars["WORKER_NAME"], env["WORKER_NAME"])
        mine = crypto.public_key(base64.b64decode(env["CFPROXY_KEY"]))
        self.assertEqual(base64.b64decode(w.vars["CFP_PUBKEY"]), mine)  # the runner seals its result for THIS machine
        # the private key never leaves the machine
        self.assertNotIn(env["CFPROXY_KEY"], list(w.secrets.values()) + list(w.vars.values()))

    def test_init_twice_changes_nothing(self):
        self.prepared()
        before = dict(self.world.files)
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)
        self.assertIn("0 written, 4 already current", err)
        self.assertEqual(self.world.files, before)

    def test_init_in_a_public_repository_if_asked(self):
        self.setup_settings()
        self.assertEqual(self.cli("init", "--public")[0], 0)
        self.assertFalse(self.world.private)

    def test_init_adds_the_files_to_a_repository_that_already_has_content(self):
        self.setup_settings()
        self.world.exists = True
        self.world.files = {"README.md": b"hello"}
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)
        self.assertIn("already holds other files", err)
        self.assertEqual(self.world.files["README.md"], b"hello")
        self.assertTrue(set(gh.DEPLOY_FILES) <= set(self.world.files))

    def test_an_outdated_file_in_the_repository_is_updated(self):
        self.prepared()
        self.world.files["worker/index.js"] = b"// old version"
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)
        self.assertIn("1 written", err)
        self.assertNotEqual(self.world.files["worker/index.js"], b"// old version")

    def test_a_secret_removed_from_the_env_file_is_removed_from_the_repository(self):
        self.prepared()
        self.assertEqual(self.cli("setup", "--non-interactive", "--domain", "")[0], 0)
        common.env_set(common.env_file(), "CUSTOM_DOMAIN", "proxy.example.com")
        self.assertEqual(self.cli("init")[0], 0)
        self.assertEqual(self.world.secrets["CUSTOM_DOMAIN"], "proxy.example.com")
        common.env_set(common.env_file(), "CUSTOM_DOMAIN", "")
        os.environ["CUSTOM_DOMAIN"] = ""
        self.assertEqual(self.cli("init")[0], 0)
        self.assertNotIn("CUSTOM_DOMAIN", self.world.secrets)

    def test_a_wrong_github_token_is_explained(self):
        self.setup_settings(**{"--github-token": "wrong"})
        code, _, err = self.cli("init")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 401", err)
        self.assertIn("github.com/settings/tokens", err)

    # ------------------------------------------------------------ check
    def test_check_before_and_after_init(self):
        self.setup_settings()
        code, _, err = self.cli("check")
        self.assertEqual(code, 1)
        self.assertIn("alice/cfproxy not found", err)
        self.assertEqual(self.cli("init")[0], 0)
        code, _, err = self.cli("check")
        self.assertEqual(code, 0, err)
        self.assertIn("deploy.yml found on main", err)

    def test_check_notices_a_classic_token_without_the_workflow_scope(self):
        self.prepared()
        self.world.scopes = "repo"
        code, _, err = self.cli("check")
        self.assertEqual(code, 1)
        self.assertIn("lacks the scope(s): workflow", err)

    def test_check_cloudflare_runs_the_workflow_and_reports_the_token(self):
        self.prepared()
        code, _, err = self.cli("check", "--cloudflare")
        self.assertEqual(code, 0, err)
        self.assertIn("the Cloudflare token is active", err)
        self.assertIn("acme.workers.dev", err)

    def test_check_cloudflare_reports_a_wrong_cloudflare_token(self):
        self.setup_settings(**{"--cf-token": "wrong-cf-token"})
        self.assertEqual(self.cli("init")[0], 0)
        code, _, err = self.cli("check", "--cloudflare")
        self.assertEqual(code, 1)
        self.assertIn("the Cloudflare token is not accepted", err)

    # ------------------------------------------------------------ deploy
    def test_deploy_puts_the_worker_on_cloudflare_and_remembers_its_address(self):
        self.prepared()
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 0, err)
        host = self.dotenv()["WORKER_HOST"]
        self.assertEqual(host, f"{self.dotenv()['WORKER_NAME']}.acme.workers.dev")
        self.assertIn(f"WORKER_HOST={host} saved", err)
        self.assertIn(self.dotenv()["WORKER_NAME"], self.cf.workers)
        calls = fakes.read_calls(self.calls_log)
        self.assertEqual([c["args"][0] for c in calls], ["deploy", "secret", "secret", "secret"])
        self.assertEqual({c["args"][2]: c["stdin"] for c in calls[1:]}, {"AUTH_TOKEN": TOKEN, "WS_PATH": WS_PATH, "ALLOW": "all"})

    def test_the_public_log_and_the_storage_host_never_see_what_must_stay_private(self):
        self.deployed()
        host = self.dotenv()["WORKER_HOST"]
        logs = "\n".join(self.world.job_logs.values())
        self.assertIn("deploying the Worker with wrangler", logs)
        for private in (host, CF_TOKEN, ACCOUNT, TOKEN, WS_PATH):
            self.assertNotIn(private, logs)
        self.assertTrue(self.world.blob_requests)
        for path, headers in self.world.blob_requests:
            self.assertNotIn("Authorization", headers, path)  # the GitHub token must not follow a redirect to another host
        # the artifact itself is sealed: the host is not readable in it
        for artifact in self.world.artifacts.values():
            self.assertNotIn(host.encode(), artifact["zip"])

    def test_deploy_as_pages(self):
        self.setup_settings(**{"--target": "pages"})
        self.assertEqual(self.cli("init")[0], 0)
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.dotenv()["WORKER_HOST"], f"{self.dotenv()['WORKER_NAME']}.pages.dev")
        self.assertEqual(fakes.read_calls(self.calls_log)[-1]["args"][:2], ["pages", "deploy"])

    def test_a_failed_deploy_shows_the_log_and_keeps_the_old_address(self):
        self.prepared()
        self.world.runner_env["FAKE_WRANGLER_FAIL"] = "deploy"
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 1)
        self.assertIn("wrangler deploy failed", err)
        self.assertRegex(err, r"GitHub run \d+ failure")
        self.assertNotIn("WORKER_HOST", self.dotenv())

    def test_a_result_sealed_for_another_key_is_explained(self):
        self.prepared()
        self.world.vars["CFP_PUBKEY"] = base64.b64encode(os.urandom(32)).decode()
        # `deploy` would repair the variable first (it syncs the settings), so skip that step to simulate the mismatch
        with mock.patch.object(gh, "sync", return_value=(0, 0, 0)):
            code, _, err = self.cli("deploy")
        self.assertEqual(code, 1)
        self.assertIn("cannot be opened with CFPROXY_KEY", err)

    def test_runs_and_fetch(self):
        self.deployed()
        code, _, err = self.cli("runs")
        self.assertEqual(code, 0)
        self.assertRegex(err, r"\d+\s+success\s+\d{4}-\d\d-\d\dT")
        os.environ.pop("WORKER_HOST", None)
        common.env_set(common.env_file(), "WORKER_HOST", "")
        code, _, err = self.cli("fetch")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.dotenv()["WORKER_HOST"], f"{self.dotenv()['WORKER_NAME']}.acme.workers.dev")

    def test_destroy_takes_the_worker_down(self):
        self.deployed()
        name = self.dotenv()["WORKER_NAME"]
        self.assertIn(name, self.cf.workers)
        code, _, err = self.cli("destroy", "--yes")
        self.assertEqual(code, 0, err)
        self.assertNotIn(name, self.cf.workers)
        self.assertEqual(self.dotenv()["WORKER_HOST"], "")

    # ------------------------------------------------------------ scan, test, status, links
    def test_scan_finds_the_working_endpoints_and_saves_them(self):
        self.deployed()
        out_file = os.path.join(self.home, "clean.txt")
        ips = os.path.join(self.home, "ips.txt")
        with open(ips, "w") as f:
            f.write("127.0.0.1\n")
        dead = self.free_port()
        code, _, err = self.cli("scan", "--ips", ips, "--ports", f"{self.plain},{dead}", "--timeout", "3", "--out", out_file)
        self.assertEqual(code, 0, err)
        self.assertIn("1 working endpoint(s)", err)
        with open(out_file) as f:
            self.assertEqual(f.read(), f"127.0.0.1:{self.plain}\n")
        endpoints, meta = common.load_endpoints()
        self.assertEqual([(e["ip"], e["port"], e["tls"]) for e in endpoints], [("127.0.0.1", self.plain, False)])
        self.assertTrue(endpoints[0]["tunnel_ms"] > 0)
        self.assertEqual(meta["host"], self.dotenv()["WORKER_HOST"])

    def test_scan_with_a_wrong_token_says_so(self):
        self.deployed()
        os.environ["AUTH_TOKEN"] = "not-what-the-worker-has"
        ips = os.path.join(self.home, "ips.txt")
        with open(ips, "w") as f:
            f.write("127.0.0.1\n")
        code, _, err = self.cli("scan", "--ips", ips, "--ports", str(self.plain), "--timeout", "3")
        self.assertEqual(code, 1)
        self.assertIn("wrong AUTH_TOKEN", err)

    def test_scan_when_nothing_answers(self):
        self.deployed()
        ips = os.path.join(self.home, "ips.txt")
        with open(ips, "w") as f:
            f.write("127.0.0.1\n")
        code, _, err = self.cli("scan", "--ips", ips, "--ports", str(self.free_port()), "--timeout", "2")
        self.assertEqual(code, 1)
        self.assertIn("no IP answered for your Worker", err)

    def test_scan_needs_a_deployment_first(self):
        self.setup_settings()
        code, _, err = self.cli("scan")
        self.assertEqual(code, 2)
        self.assertIn("WORKER_HOST is not set", err)

    def test_test_proves_the_path_again_and_shows_the_exit_address(self):
        self.deployed()
        self.scanned()
        code, _, err = self.cli("test", "--count", "3")
        self.assertEqual(code, 0, err)
        self.assertIn("Telegram answered in", err)
        self.assertIn("1 of 1 endpoint(s) carry a tunnel to Telegram", err)
        server = self.fx._run(asyncio.start_server(self.http_ip, "127.0.0.1", 0))
        self.addCleanup(self.fx.loop.call_soon_threadsafe, server.close)
        with mock.patch.object(cfproxy, "EXIT_IP_TARGET", ("127.0.0.1", server.sockets[0].getsockname()[1])):
            code, _, err = self.cli("test", "--exit-ip")
        self.assertEqual(code, 0, err)
        self.assertIn("203.0.113.7", err)

    @staticmethod
    async def http_ip(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n203.0.113.7\n")
        await writer.drain()
        writer.close()

    def test_status_reports_settings_the_scan_and_the_deployment(self):
        self.deployed()
        self.scanned()
        os.environ["WORKER_HOST"] = "127.0.0.1"  # a host that does not answer on 443: the saved endpoint must
        code, _, err = self.cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("cfproxy 1.0.0", err)
        self.assertIn(f"127.0.0.1:{self.plain}", err)
        self.assertIn("it answers through the clean endpoint", err)
        self.assertNotIn(TOKEN, err)  # secrets are masked
        self.assertNotIn(self.dotenv()["CF_API_TOKEN"], err)

    def test_links_use_the_secret_and_the_login(self):
        self.deployed()
        env = self.dotenv()
        out_file = os.path.join(self.home, "links.txt")
        code, out, err = self.cli("links", "--socks-port", "1081", "--mtproto-port", "1444", "--out", out_file)
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        self.assertIn(f"tg://proxy?server=127.0.0.1&port=1444&secret=dd{SECRET_HEX}", lines)
        self.assertIn(f"https://t.me/proxy?server=127.0.0.1&port=1444&secret=dd{SECRET_HEX}", lines)
        self.assertTrue(any(l.startswith("tg://socks?server=127.0.0.1&port=1081&user=" + env["SOCKS_USER"]) for l in lines))
        self.assertTrue(any(l.startswith(f"socks5://{env['SOCKS_USER']}:") and l.endswith("@127.0.0.1:1081") for l in lines))
        with open(out_file) as f:
            self.assertEqual(f.read().split(), lines)
        code, out, _ = self.cli("links", "--host", "192.168.1.20")
        self.assertIn("server=192.168.1.20", out)

    def test_an_mtproto_only_worker_has_no_socks_links(self):
        self.setup_settings(**{"--allow": "telegram"})
        code, out, err = self.cli("links")
        self.assertEqual(code, 0, err)
        self.assertIn("tg://proxy?", out)
        self.assertNotIn("socks", out)

    # ------------------------------------------------------------ serve: a real bridge process
    def start_serve(self, *extra):
        env = {"PATH": os.environ["PATH"], "CFPROXY_HOME": self.home, "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"}
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "lib", "cfproxy.py"), "serve", "--socks-port", "0",
                                 "--mtproto-port", "0", *extra], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        self.addCleanup(self.stop_serve, proc)
        lines, got_all = [], threading.Event()

        def reader():
            for line in proc.stdout:
                lines.append(line.strip())
                if any(l.startswith("socks5://") for l in lines) and any(l.startswith("tg://proxy?") for l in lines):
                    got_all.set()
        threading.Thread(target=reader, daemon=True).start()
        if not got_all.wait(20):
            proc.kill()
            self.fail("serve printed no links: " + proc.stderr.read())
        return proc, lines

    @staticmethod
    def stop_serve(proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for stream in (proc.stdout, proc.stderr):
            stream.close()

    def test_serve_gives_working_socks5_and_mtproto_proxies(self):
        self.deployed()
        self.scanned()
        proc, lines = self.start_serve("--allow-plain-socks")
        socks = next(re.match(r"socks5://([^:]+):([^@]+)@127\.0\.0\.1:(\d+)$", l) for l in lines if l.startswith("socks5://"))
        user, password, socks_port = socks.group(1), socks.group(2), int(socks.group(3))
        mt_link = next(l for l in lines if l.startswith("tg://proxy?"))
        mt_port = int(re.search(r"port=(\d+)", mt_link).group(1))
        self.assertIn("secret=dd" + SECRET_HEX, mt_link)

        async def through_both():
            reader, writer, code = await socks_open(socks_port, "127.0.0.1", self.fx.echo.port, user, password)
            self.assertEqual(code, 0)
            writer.write(b"through the whole chain")
            self.assertEqual(await asyncio.wait_for(reader.readexactly(23), 15), b"through the whole chain")
            writer.close()
            _, writer, code = await socks_open(socks_port, "127.0.0.1", self.fx.echo.port, user, "wrong-password")
            self.assertEqual(code, -2)
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", mt_port)

            async def send(data):
                writer.write(data)
                await writer.drain()

            async def recv():
                return (await reader.read(65536)) or None

            result = await mt.probe_telegram(send, recv, dc=2, secret=bytes.fromhex(SECRET_HEX), timeout=15)
            writer.close()
            return result

        result = asyncio.run(through_both())
        self.assertTrue(result["ok"], result)
        proc.send_signal(signal.SIGINT)
        self.assertEqual(proc.wait(15), 0)

    def test_serve_keeps_socks5_off_the_plain_http_ports_by_default(self):
        self.deployed()
        self.scanned()
        env = {"PATH": os.environ["PATH"], "CFPROXY_HOME": self.home, "NO_COLOR": "1"}
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "lib", "cfproxy.py"), "serve", "--socks-port", "0",
                                 "--mtproto-port", "0"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_serve, proc)
        first = proc.stdout.readline()
        self.assertTrue(first.startswith("tg://proxy?"), first)  # MTProto only
        proc.send_signal(signal.SIGINT)
        proc.wait(15)
        self.assertIn("SOCKS5 is off", proc.stderr.read())

    def test_serve_on_the_network_needs_a_socks_login(self):
        self.deployed()
        self.scanned()
        common.env_set(common.env_file(), "SOCKS_USER", "")
        os.environ["SOCKS_USER"] = ""
        code, _, err = self.cli("serve", "--listen", "0.0.0.0", "--allow-plain-socks")
        self.assertEqual(code, 2)
        self.assertIn("needs SOCKS_USER / SOCKS_PASS", err)

    @staticmethod
    def free_port():
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port


if __name__ == "__main__":
    unittest.main()
