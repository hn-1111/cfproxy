"""The whole chain with Railway as the exit, driven through the command line (lib/cfproxy.py):

  setup (target railway) -> init -> deploy (the fake GitHub runs the REAL workflow + cfp_deploy.py; a fake Railway API really
  starts the shipped Node server) -> scan (DNS of the domain) -> serve (a real bridge process: SOCKS5 and MTProto through the
  REAL server/index.mjs) -> destroy
"""
import asyncio
import contextlib
import io
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import helpers
from helpers import DEFAULT_TARGET, HAVE_NODE, ROOT, SECRET_HEX, TG_DCS, TG_PORT, TOKEN, WS_PATH, fixtures

import cfp_common as common
import cfp_gh as gh
import cfproxy
import cfp_mtproto as mt
import fakes
from test_bridge import socks_open

try:
    import yaml
except ImportError:
    yaml = None

RW_TOKEN = "rw-chain-token"


@unittest.skipUnless(HAVE_NODE and yaml is not None, "needs node and PyYAML")
class RailwayChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cfp-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.world = fakes.GitHubWorld()
        server, github_url = fakes.start_github(self.world)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        # every Telegram address lands on the fake data centre, exactly as with the Cloudflare edge of the other chain test
        addresses = {f"{ip}:{TG_PORT}" for options in TG_DCS.values() for ip in options}
        addresses.add("%s:%d" % DEFAULT_TARGET)
        remap = ",".join(f"{a}=127.0.0.1:{self.fx.telegram.port}" for a in sorted(addresses))
        self.rw = fakes.FakeRailway(token=RW_TOKEN, remap=remap, extra_env={"CFP_ALLOW_PRIVATE": "1"}).start()  # the echo target is local
        self.addCleanup(self.rw.stop)
        self.world.runner_env = {
            "PATH": os.environ["PATH"], "RAILWAY_API_BASE": self.rw.url, "CFP_POLL_SECONDS": "0.05", "CFP_RETRY_SECONDS": "0",
            "CFP_VERIFY_URL": f"http://127.0.0.1:{self.rw.app_port}{WS_PATH}/health"}
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in list(os.environ):
            if name.startswith(("CFP_", "CFPROXY_")) or name in (
                    "GITHUB_API_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "CF_API_TOKEN",
                    "CF_ACCOUNT_ID", "WORKER_HOST", "WORKER_NAME", "CUSTOM_DOMAIN", "ALLOW", "AUTH_TOKEN", "WS_PATH",
                    "MTPROTO_SECRET", "SOCKS_USER", "SOCKS_PASS", "PUBLIC_HOST", "RAILWAY_API_TOKEN", "RAILWAY_WORKSPACE_ID",
                    "RAILWAY_REGION"):
                del os.environ[name]
        os.environ.update({"CFPROXY_HOME": self.home, "GITHUB_API_BASE": github_url, "CFP_GH_POLL_SECONDS": "0.05",
                           "CFP_GH_RETRY_SECONDS": "0", "CFP_GH_START_TIMEOUT": "20", "NO_COLOR": "1"})
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
        values = {"--github-token": self.world.token, "--repo": "alice/cfproxy", "--target": "railway",
                  "--railway-token": RW_TOKEN, "--allow": "all"}
        values.update(overrides)
        argv = ["setup", "--non-interactive"] + [x for pair in values.items() for x in pair]
        code, _, err = self.cli(*argv)
        self.assertEqual(code, 0, err)
        return err

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

    def scanned(self):
        host = self.dotenv()["WORKER_HOST"]
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(cfproxy.socket, "getaddrinfo", return_value=answer) as lookup:
            code, _, err = self.cli("scan", "--ports", str(self.rw.app_port), "--timeout", "3")
        self.assertEqual(code, 0, err)
        self.assertEqual(lookup.call_args[0][0], host)
        return err

    # ------------------------------------------------------------ setup and init
    def test_setup_asks_for_the_railway_token_and_not_for_cloudflare(self):
        err = self.setup_settings()
        env = self.dotenv()
        self.assertEqual((env["CFP_TARGET"], env["RAILWAY_API_TOKEN"]), ("railway", RW_TOKEN))
        self.assertNotIn("CF_API_TOKEN", env)
        self.assertNotIn("CF_ACCOUNT_ID", env)
        self.assertIn("Acceptable Use Policy", err)  # said at the moment of choosing
        self.assertEqual(os.stat(common.env_file()).st_mode & 0o777, 0o600)

    def test_setup_for_railway_without_the_railway_token_is_refused(self):
        code, _, err = self.cli("setup", "--non-interactive", "--github-token", "x", "--repo", "alice/cfproxy", "--target", "railway")
        self.assertEqual(code, 2)
        self.assertIn("RAILWAY_API_TOKEN", err)

    def test_the_cloudflare_questions_are_still_asked_for_worker_and_pages(self):
        code, _, err = self.cli("setup", "--non-interactive", "--github-token", "x", "--repo", "alice/cfproxy", "--target", "worker")
        self.assertEqual(code, 2)
        self.assertIn("CF_API_TOKEN", err)

    def test_setup_keeps_the_optional_railway_settings(self):
        self.setup_settings(**{"--railway-region": "europe-west4-drams3a", "--railway-workspace": "ws-1"})
        env = self.dotenv()
        self.assertEqual((env["RAILWAY_REGION"], env["RAILWAY_WORKSPACE_ID"]), ("europe-west4-drams3a", "ws-1"))

    def test_init_sends_the_railway_settings_and_every_file_the_runner_needs(self):
        self.setup_settings(**{"--railway-region": "europe-west4-drams3a"})
        code, _, err = self.cli("init")
        self.assertEqual(code, 0, err)
        w = self.world
        self.assertEqual(set(w.files), set(gh.DEPLOY_FILES))
        self.assertIn("server/index.mjs", w.files)
        for rel in gh.DEPLOY_FILES:
            with open(os.path.join(ROOT, *rel.split("/")), "rb") as f:
                self.assertEqual(w.files[rel], f.read(), rel)
        self.assertEqual(w.secrets, {"RAILWAY_API_TOKEN": RW_TOKEN, "AUTH_TOKEN": TOKEN, "WS_PATH": WS_PATH})
        self.assertEqual(set(w.vars), {"WORKER_NAME", "ALLOW", "CFP_PUBKEY", "RAILWAY_REGION"})
        self.assertEqual(w.vars["RAILWAY_REGION"], "europe-west4-drams3a")

    def test_check_knows_which_secrets_railway_needs(self):
        self.setup_settings()
        self.assertNotEqual(self.cli("check")[0], 0)  # nothing is in the repository yet
        self.assertEqual(self.cli("init")[0], 0)
        code, _, err = self.cli("check")
        self.assertEqual(code, 0, err)

    def test_check_remote_runs_the_workflow_and_reports_the_railway_token(self):
        self.prepared()
        code, _, err = self.cli("check", "--remote")
        self.assertEqual(code, 0, err)
        self.assertIn("the Railway token is accepted", err)
        self.assertEqual(self.rw.projects, {})
        common.env_set(common.env_file(), "RAILWAY_API_TOKEN", "a-wrong-token")
        os.environ["RAILWAY_API_TOKEN"] = "a-wrong-token"
        self.assertEqual(self.cli("init")[0], 0)
        code, _, err = self.cli("check", "--remote")
        self.assertNotEqual(code, 0)
        self.assertIn("Not Authorized", err)

    def test_status_shows_the_railway_token_row(self):
        self.setup_settings()
        code, out, err = self.cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("railway token", out + err)
        self.assertNotIn("cloudflare token", out + err)

    # ------------------------------------------------------------ deploy and destroy
    def test_deploy_puts_the_exit_on_railway_and_remembers_its_address(self):
        self.prepared()
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 0, err)
        self.assertIn("Acceptable Use Policy", err)  # and again before the first deployment
        env = self.dotenv()
        project = next(iter(self.rw.projects.values()))
        service = next(iter(project["services"].values()))
        self.assertEqual(project["name"], env["WORKER_NAME"])
        self.assertEqual(env["WORKER_HOST"], service["domains"][0])
        self.assertIn(f"WORKER_HOST={env['WORKER_HOST']} saved", err)
        self.assertEqual(service["variables"]["AUTH_TOKEN"], TOKEN)

    def test_deploy_twice_keeps_the_same_address(self):
        self.deployed()
        first = self.dotenv()["WORKER_HOST"]
        code, _, err = self.cli("deploy")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.dotenv()["WORKER_HOST"], first)
        self.assertEqual((self.rw.count("projectCreate"), self.rw.count("serviceCreate")), (1, 1))

    def test_the_public_log_never_sees_what_must_stay_private(self):
        self.deployed()
        host = self.dotenv()["WORKER_HOST"]
        logs = "\n".join(self.world.job_logs.values())
        self.assertIn("creating the Railway project", logs)
        for private in (host, RW_TOKEN, TOKEN, WS_PATH):
            self.assertNotIn(private, logs)
        for artifact in self.world.artifacts.values():
            self.assertNotIn(host.encode(), artifact["zip"])  # sealed

    def test_a_crashed_deployment_shows_the_log_and_keeps_the_old_address(self):
        self.deployed()
        before = self.dotenv()["WORKER_HOST"]
        self.rw.deploy_status = "CRASHED"
        code, _, err = self.cli("deploy")
        self.assertNotEqual(code, 0)
        self.assertIn("crashed", err)
        self.assertEqual(self.dotenv()["WORKER_HOST"], before)

    def test_destroy_takes_it_down_and_forgets_the_address(self):
        self.deployed()
        self.assertEqual(len(self.rw.projects), 1)
        code, _, err = self.cli("destroy", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rw.projects, {})
        self.assertEqual(self.dotenv()["WORKER_HOST"], "")

    # ------------------------------------------------------------ scan, serve
    def test_scan_resolves_the_domain_and_keeps_what_answers(self):
        self.deployed()
        err = self.scanned()
        self.assertIn("resolves to 127.0.0.1", err)
        self.assertIn("1 working endpoint(s)", err)
        endpoints, meta = common.load_endpoints()
        self.assertEqual([(e["ip"], e["port"], e["tls"]) for e in endpoints], [("127.0.0.1", self.rw.app_port, False)])
        self.assertEqual(meta["host"], self.dotenv()["WORKER_HOST"])

    def test_scan_says_so_when_the_domain_cannot_be_resolved(self):
        self.deployed()
        with mock.patch.object(cfproxy.socket, "getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            code, _, err = self.cli("scan", "--ports", str(self.rw.app_port))
        self.assertEqual(code, 2)
        self.assertIn("cannot resolve", err)
        self.assertIn("--ips FILE", err)

    def test_scan_with_an_address_file_still_works(self):
        self.deployed()
        ips = os.path.join(self.home, "ips.txt")
        with open(ips, "w") as f:
            f.write("127.0.0.1\n")
        code, _, err = self.cli("scan", "--ips", ips, "--ports", str(self.rw.app_port), "--timeout", "3")
        self.assertEqual(code, 0, err)
        self.assertIn("1 working endpoint(s)", err)

    def start_serve(self, *extra):
        env = {"PATH": os.environ["PATH"], "CFPROXY_HOME": self.home, "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"}
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "lib", "cfproxy.py"), "serve", "--socks-port", "0",
                                 "--mtproto-port", "0", *extra], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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

    def test_serve_gives_working_socks5_and_mtproto_proxies_through_the_railway_server(self):
        self.deployed()
        self.scanned()
        proc, lines = self.start_serve("--allow-plain-socks")
        socks = next(re.match(r"socks5://([^:]+):([^@]+)@127\.0\.0\.1:(\d+)$", l) for l in lines if l.startswith("socks5://"))
        user, password, socks_port = socks.group(1), socks.group(2), int(socks.group(3))
        mt_link = next(l for l in lines if l.startswith("tg://proxy?"))
        mt_port = int(re.search(r"port=(\d+)", mt_link).group(1))

        async def through_both():
            reader, writer, code = await socks_open(socks_port, "127.0.0.1", self.fx.echo.port, user, password)
            self.assertEqual(code, 0)
            writer.write(b"through the whole chain")
            self.assertEqual(await asyncio.wait_for(reader.readexactly(23), 15), b"through the whole chain")
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


if __name__ == "__main__":
    unittest.main()
