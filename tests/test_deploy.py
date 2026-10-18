"""cfp_deploy.py, the script the GitHub runner executes: a fake Cloudflare API, a fake `npx wrangler` and the real
Worker code (behind the local edge) that answers the final health check."""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import helpers
from helpers import HAVE_NODE, ROOT

import cfp_crypto as crypto
import cfp_deploy as deploy
import fakes

AUTH = "deploy-test-token-" + "y" * 20
WS = "/abc123def456"
ACCOUNT = "a" * 32


def project_copy() -> str:
    """The checkout the runner would have: lib/ and worker/ only."""
    folder = tempfile.mkdtemp(prefix="cfp-checkout-")
    for name in ("lib", "worker"):
        shutil.copytree(os.path.join(ROOT, name), os.path.join(folder, name),
                        ignore=shutil.ignore_patterns("__pycache__"))
    return folder


@unittest.skipUnless(HAVE_NODE, "needs node")
class OnTheRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.edge = helpers.Edge(auth=AUTH, ws_path=WS, tls=False).start()

    @classmethod
    def tearDownClass(cls):
        cls.edge.stop()

    def setUp(self):
        self.cf = fakes.FakeCloudflare(account=ACCOUNT).start()
        self.addCleanup(self.cf.stop)
        self.checkout = project_copy()
        self.addCleanup(shutil.rmtree, self.checkout, True)
        self.bin = tempfile.mkdtemp(prefix="cfp-bin-")
        self.addCleanup(shutil.rmtree, self.bin, True)
        self.calls_log = fakes.install_fake_npx(self.bin)
        self.sk, self.pk = crypto.generate_keypair()
        self.result_file = os.path.join(self.checkout, "out", "result.bin")

    def run_script(self, action="deploy", target="worker", **extra):
        env = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "HOME": self.checkout, "CFP_ACTION": action,
               "CFP_TARGET": target, "CF_API_TOKEN": self.cf.token, "CF_ACCOUNT_ID": ACCOUNT, "AUTH_TOKEN": AUTH,
               "WS_PATH": WS, "WORKER_NAME": "my-proxy", "ALLOW": "all", "CFP_RESULT_FILE": self.result_file,
               "CFP_PUBKEY": base64.b64encode(self.pk).decode(), "CF_API_BASE": self.cf.url,
               "CFP_VERIFY_URL": f"http://127.0.0.1:{self.edge.plain}{WS}/health",
               "FAKE_WRANGLER_LOG": self.calls_log, "FAKE_SUBDOMAIN": "acme"}
        env.update(extra)
        env = {k: v for k, v in env.items() if v is not None}
        proc = subprocess.run([sys.executable, os.path.join(self.checkout, "lib", "cfp_deploy.py")], cwd=self.checkout,
                              env=env, capture_output=True, text=True, timeout=120)
        return proc, self.read_result()

    def read_result(self):
        try:
            with open(self.result_file, "rb") as f:
                sealed = f.read()
        except OSError:
            return None
        return json.loads(crypto.open_sealed(sealed, self.pk, self.sk).decode("utf-8"))

    def wrangler(self):
        return fakes.read_calls(self.calls_log)

    def read_config(self):
        with open(os.path.join(self.checkout, "build", "wrangler.toml"), encoding="utf-8") as f:
            return f.read()

    # ------------------------------------------------------------ worker
    def test_a_worker_is_deployed_and_the_result_comes_back_sealed(self):
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])
        self.assertEqual((result["action"], result["target"], result["host"]), ("deploy", "worker", "my-proxy.acme.workers.dev"))
        self.assertEqual(result["v"], 1)
        self.assertIn("the deployment answers on its health address", result["log"])
        self.assertIn("my-proxy.acme.workers.dev", result["log"])  # the sealed log is complete

    def test_wrangler_gets_the_config_then_the_secrets_through_stdin_only(self):
        proc, _ = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.wrangler()
        self.assertEqual([c["args"][0] for c in calls], ["deploy", "secret", "secret", "secret"])
        self.assertEqual({c["args"][2]: c["stdin"] for c in calls[1:]},
                         {"AUTH_TOKEN": AUTH, "WS_PATH": WS, "ALLOW": "all"})
        for call in calls:
            self.assertTrue(call["token_ok"] and call["account_ok"])
            self.assertEqual(call["leaked_env"], [])  # wrangler never sees the tunnel secrets in its environment
            self.assertNotIn(AUTH, " ".join(call["args"]))  # nor on a command line
            self.assertNotIn(WS, " ".join(call["args"]))
        config = self.read_config()
        self.assertIn('name = "my-proxy"', config)
        self.assertIn("workers_dev = true", config)
        self.assertNotIn("routes", config)

    def test_the_log_on_stdout_masks_hosts_and_tokens_before_anything_prints_them(self):
        proc, _ = self.run_script()
        masked = {line[len("::add-mask::"):] for line in proc.stdout.splitlines() if line.startswith("::add-mask::")}
        self.assertTrue({"my-proxy.acme.workers.dev", AUTH, WS, self.cf.token, ACCOUNT} <= masked, masked)
        public = fakes.public_log(proc.stdout, [])  # what a stranger reading the Actions log of a public repository sees
        self.assertIn("***", public)
        for secret in (AUTH, self.cf.token, "my-proxy.acme.workers.dev"):
            self.assertNotIn(secret, public)

    def test_a_custom_domain_is_routed_and_becomes_the_host(self):
        proc, result = self.run_script(CUSTOM_DOMAIN="Proxy.Example.com")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(result["host"], "proxy.example.com")
        config = self.read_config()
        self.assertIn('routes = [{ pattern = "proxy.example.com", custom_domain = true }]', config)

    def test_an_account_without_a_workers_dev_address_gets_one(self):
        self.cf.subdomain = None
        proc, result = self.run_script(FAKE_SUBDOMAIN="unused")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.cf.subdomain.startswith("cfp-"))
        self.assertIn("registering one", result["log"])

    def test_a_failing_wrangler_gives_a_failed_result_with_the_log(self):
        proc, result = self.run_script(FAKE_WRANGLER_FAIL="deploy")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(result["ok"])
        self.assertIn("wrangler deploy failed", result["log"])
        self.assertEqual([c["args"][0] for c in self.wrangler()], ["deploy"])  # no secrets after a failed deploy

    def test_a_wrong_cloudflare_token_is_explained(self):
        proc, result = self.run_script(CF_API_TOKEN="not-the-token")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(result["ok"])
        self.assertIn("the token is wrong, expired or lacks a permission", result["log"])
        self.assertEqual(self.wrangler(), [])

    def test_a_bad_setting_stops_before_anything_is_called(self):
        for name, value, words in (("CF_ACCOUNT_ID", "short", "32-character"), ("WORKER_NAME", "Bad_Name", "WORKER_NAME"),
                                   ("AUTH_TOKEN", None, "AUTH_TOKEN is not set"), ("WS_PATH", "no-slash", "WS_PATH"),
                                   ("ALLOW", "everything", "ALLOW"), ("CUSTOM_DOMAIN", "not a host", "CUSTOM_DOMAIN")):
            proc, result = self.run_script(**{name: value})
            self.assertEqual(proc.returncode, 1, name)
            self.assertIn(words, result["log"], name)
        self.assertEqual(self.cf.calls, [])
        self.assertEqual(self.wrangler(), [])

    def test_without_a_public_key_there_is_no_result_file(self):
        proc, result = self.run_script(CFP_PUBKEY="")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIsNone(result)
        self.assertIn("CFP_PUBKEY is missing or damaged", proc.stdout)

    def test_the_result_opens_only_with_the_matching_key(self):
        self.run_script()
        with open(self.result_file, "rb") as f:
            sealed = f.read()
        other_sk, other_pk = crypto.generate_keypair()
        with self.assertRaises(crypto.CryptoError):
            crypto.open_sealed(sealed, other_pk, other_sk)
        self.assertNotIn(b"workers.dev", sealed)

    # ------------------------------------------------------------ pages
    def test_a_pages_project_is_created_and_deployed_with_the_secrets_set_first(self):
        proc, result = self.run_script(target="pages")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(result["host"], "my-proxy.pages.dev")
        calls = self.wrangler()
        self.assertEqual([" ".join(c["args"][:3]) for c in calls[:4]],
                         ["pages project create", "pages secret put", "pages secret put", "pages secret put"])
        self.assertEqual(calls[-1]["args"][:2], ["pages", "deploy"])  # Pages applies secrets to the NEXT deployment
        self.assertEqual(len(calls), 5)
        self.assertTrue(os.path.exists(os.path.join(self.checkout, "build", "pages", "_worker.js")))
        with open(os.path.join(self.checkout, "worker", "index.js"), "rb") as a, \
                open(os.path.join(self.checkout, "build", "pages", "_worker.js"), "rb") as b:
            self.assertEqual(a.read(), b.read())  # the very same code as the Worker

    def test_an_existing_pages_project_is_not_created_again(self):
        self.cf.pages["my-proxy"] = {"subdomain": "my-proxy.pages.dev"}
        proc, result = self.run_script(target="pages")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("project", [c["args"][1] for c in self.wrangler()])
        self.assertEqual(result["host"], "my-proxy.pages.dev")

    # ------------------------------------------------------------ destroy and check
    def test_destroy_deletes_the_worker_and_clears_the_host(self):
        self.cf.workers.add("my-proxy")
        proc, result = self.run_script("destroy")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((result["ok"], result["action"], result["host"]), (True, "destroy", ""))
        self.assertNotIn("my-proxy", self.cf.workers)
        self.assertEqual(self.wrangler(), [])

    def test_destroy_is_fine_when_there_is_nothing_to_delete(self):
        proc, result = self.run_script("destroy", "pages")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])

    def test_check_verifies_the_token_and_reports_the_address(self):
        proc, result = self.run_script("check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the Cloudflare token is active", result["log"])
        self.assertIn("acme.workers.dev", result["log"])
        self.assertEqual(self.wrangler(), [])

    def test_check_accepts_an_account_token(self):
        self.cf.verify_user_tokens = False
        proc, result = self.run_script("check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])


class Pieces(unittest.TestCase):
    def test_host_from_output(self):
        out = "Deployed my-proxy (1 sec)\n  https://my-proxy.acme.workers.dev\n  https://other.acme.workers.dev"
        self.assertEqual(deploy.host_from_output(out, "my-proxy", "worker"), "my-proxy.acme.workers.dev")
        self.assertEqual(deploy.host_from_output("see https://1a2b3c4d.my-proxy.pages.dev ok", "my-proxy", "pages"),
                         "my-proxy.pages.dev")
        self.assertEqual(deploy.host_from_output("nothing here", "my-proxy", "worker"), "")

    def test_names_domains_and_paths(self):
        self.assertTrue(deploy.NAME_RE.match("cfproxy-1a2b3c"))
        for bad in ("-a", "a-", "A", "a_b", "", "a" * 53):
            self.assertFalse(deploy.NAME_RE.match(bad), bad)
        self.assertTrue(deploy.DOMAIN_RE.match("proxy.example.com"))
        self.assertFalse(deploy.DOMAIN_RE.match("localhost"))
        self.assertTrue(deploy.PATH_RE.match("/0a1b2c3d4e5f6a7b"))
        self.assertFalse(deploy.PATH_RE.match("/a b"))
        self.assertFalse(deploy.PATH_RE.match("ws"))

    def test_the_health_check_gives_up_with_a_reason(self):
        with mock.patch.dict(os.environ, {"CFP_VERIFY_URL": "http://127.0.0.1:9/ws/health"}):
            cfg = deploy.Config()
            with self.assertRaises(deploy.DeployError) as caught:
                deploy.verify_health(cfg, "x.workers.dev", attempts=2, pause=0.01)
        self.assertIn("does not answer on its health address", str(caught.exception))

    @unittest.skipUnless(HAVE_NODE, "needs node")
    def test_the_health_check_notices_a_worker_without_its_token(self):
        with helpers.Edge(auth="", ws_path=WS, tls=False) as edge:
            url = f"http://127.0.0.1:{edge.plain}{WS}/health"
            with mock.patch.dict(os.environ, {"CFP_VERIFY_URL": url}):
                with self.assertRaises(deploy.DeployError) as caught:
                    deploy.verify_health(deploy.Config(), "x.workers.dev", attempts=2, pause=0.01)
        self.assertIn("has no AUTH_TOKEN yet", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
