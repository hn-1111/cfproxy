"""cfp_deploy.py with CFP_TARGET=railway, the script the GitHub runner executes: a fake Railway GraphQL API that really starts
what is shipped to it (the start command, the variables and the assembled tunnel app), and the real health check."""
import base64
import gzip
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import helpers
from helpers import HAVE_NODE, ROOT

import cfp_crypto as crypto
import cfp_deploy as deploy
import fakes

AUTH = "railway-test-token-" + "z" * 20
WS = "/r41lw4y5ecret"


def project_copy() -> str:
    """The checkout the runner would have: lib/, worker/ and server/ only."""
    folder = tempfile.mkdtemp(prefix="cfp-checkout-")
    for name in ("lib", "worker", "server"):
        shutil.copytree(os.path.join(ROOT, name), os.path.join(folder, name), ignore=shutil.ignore_patterns("__pycache__"))
    return folder


class TheApp(unittest.TestCase):
    """What is shipped: the Worker's own code inside the Node server."""

    def test_the_worker_code_is_pasted_in_and_the_cloudflare_import_is_gone(self):
        app = deploy.railway_app(ROOT)
        with open(os.path.join(ROOT, "worker", "index.js"), encoding="utf-8") as f:
            worker = f.read()
        self.assertNotIn(deploy.WORKER_IMPORT, app)
        self.assertNotRegex(app, r'(?m)^\s*import\b.*cloudflare:sockets')  # nothing that Node would try to load
        self.assertNotIn(deploy.APP_MARKER, app)
        self.assertIn(worker.replace(deploy.WORKER_IMPORT, deploy.WORKER_STUB), app)  # all of the Worker, but that one line

    def test_the_variable_is_small_and_decodes_to_the_app(self):
        value = deploy.railway_app_value(ROOT)
        self.assertLess(len(value), 30000)
        self.assertEqual(gzip.decompress(base64.b64decode(value)).decode("utf-8"), deploy.railway_app(ROOT))
        self.assertEqual(value, deploy.railway_app_value(ROOT))  # the same every time

    def test_the_start_command_is_a_shell_that_expands_the_variable(self):
        argv = shlex.split(deploy.START_COMMAND)
        self.assertEqual(argv[:2], ["/bin/sh", "-c"])
        self.assertEqual(len(argv), 3)
        self.assertIn("$CFP_APP", argv[2])
        self.assertTrue(argv[2].rstrip().split()[-2:] == ["node", "/tmp/cfp.mjs"])

    def test_a_changed_worker_import_is_noticed(self):
        folder = project_copy()
        self.addCleanup(shutil.rmtree, folder, True)
        path = os.path.join(folder, "worker", "index.js")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace(deploy.WORKER_IMPORT, 'import { connect as tcp } from "cloudflare:sockets";'))
        with self.assertRaises(deploy.DeployError):
            deploy.railway_app(folder)


@unittest.skipUnless(HAVE_NODE, "needs node")
class OnTheRunner(unittest.TestCase):
    def setUp(self):
        self.rw = fakes.FakeRailway().start()
        self.addCleanup(self.rw.stop)
        self.checkout = project_copy()
        self.addCleanup(shutil.rmtree, self.checkout, True)
        self.sk, self.pk = crypto.generate_keypair()
        self.result_file = os.path.join(self.checkout, "out", "result.bin")

    def run_script(self, action="deploy", **extra):
        env = {"PATH": os.environ["PATH"], "HOME": self.checkout, "CFP_ACTION": action, "CFP_TARGET": "railway",
               "RAILWAY_API_TOKEN": self.rw.token, "RAILWAY_API_BASE": self.rw.url, "AUTH_TOKEN": AUTH, "WS_PATH": WS,
               "WORKER_NAME": "my-proxy", "ALLOW": "all", "CFP_RESULT_FILE": self.result_file,
               "CFP_PUBKEY": base64.b64encode(self.pk).decode(), "CFP_POLL_SECONDS": "0.05", "CFP_RETRY_SECONDS": "0",
               "CFP_VERIFY_URL": f"http://127.0.0.1:{self.rw.app_port}{WS}/health"}
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

    def only_project(self):
        self.assertEqual(len(self.rw.projects), 1)
        return next(iter(self.rw.projects.values()))

    # ------------------------------------------------------------ deploy
    def test_a_first_deploy_creates_everything_and_the_result_comes_back_sealed(self):
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        project = self.only_project()
        service = next(iter(project["services"].values()))
        self.assertEqual((project["name"], service["name"], service["image"]), ("my-proxy", "edge", deploy.RAILWAY_IMAGE))
        self.assertEqual(service["startCommand"], deploy.START_COMMAND)
        self.assertEqual(service["targetPort"], int(deploy.RAILWAY_PORT))
        self.assertIs(service.get("sleepApplication"), False)
        self.assertEqual(service["variables"]["AUTH_TOKEN"], AUTH)
        self.assertEqual((service["variables"]["WS_PATH"], service["variables"]["ALLOW"]), (WS, "all"))
        self.assertEqual(service["variables"]["PORT"], deploy.RAILWAY_PORT)
        self.assertEqual(service["variables"]["CFP_APP"], deploy.railway_app_value(ROOT))
        self.assertTrue(result["ok"])
        self.assertEqual((result["action"], result["target"], result["host"]), ("deploy", "railway", service["domains"][0]))
        self.assertTrue(result["host"].endswith(".up.railway.app"))
        self.assertIn("the deployment answers on its health address", result["log"])

    def test_the_app_that_runs_is_the_one_that_was_shipped(self):
        proc, _ = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        service = next(iter(self.only_project()["services"].values()))
        shipped = [d for d in service["deployments"] if d["proc"] is not None and not d["removed"]]
        self.assertEqual(len(shipped), 1)
        self.assertTrue(any("listening on" in line and "configured" in line for line in shipped[0]["log"]))

    def test_the_secrets_stay_out_of_the_log(self):
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"::add-mask::{AUTH}", proc.stdout)
        self.assertIn(f"::add-mask::{self.rw.token}", proc.stdout)
        self.assertNotIn(self.rw.token, result["log"].replace("::add-mask::" + self.rw.token, ""))

    def test_a_second_deploy_reuses_the_project_service_and_domain(self):
        self.assertEqual(self.run_script()[0].returncode, 0)
        first_host = next(iter(self.only_project()["services"].values()))["domains"][0]
        proc, result = self.run_script(AUTH_TOKEN="a-new-token-" + "q" * 20)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.rw.count("projectCreate"), 1)
        self.assertEqual(self.rw.count("serviceCreate"), 1)
        self.assertEqual(self.rw.count("serviceDomainCreate"), 1)
        service = next(iter(self.only_project()["services"].values()))
        self.assertEqual(service["variables"]["AUTH_TOKEN"], "a-new-token-" + "q" * 20)
        self.assertEqual(result["host"], first_host)
        running = [d for d in service["deployments"] if not d["removed"] and d["proc"] is not None]
        self.assertEqual(len(running), 1)  # the old deployment was replaced

    def test_the_region_and_the_workspace_are_passed_on(self):
        proc, _ = self.run_script(RAILWAY_REGION="europe-west4-drams3a", RAILWAY_WORKSPACE_ID=self.rw.workspace_id)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(next(iter(self.only_project()["services"].values()))["region"], "europe-west4-drams3a")
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)
        self.assertEqual(self.rw.count("workspace"), 1)  # the existing projects were listed through the workspace

    def test_a_workspace_token_works_without_me(self):
        self.rw.workspace_token = True
        proc, result = self.run_script(RAILWAY_WORKSPACE_ID=self.rw.workspace_id)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("workspace token", result["log"])

    def test_a_custom_domain_is_not_used_and_says_so(self):
        proc, result = self.run_script(CUSTOM_DOMAIN="proxy.example.com")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("CUSTOM_DOMAIN is not used with Railway", result["log"])

    def test_nothing_has_to_be_given_the_workspace_is_found_by_itself(self):
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)
        self.assertIn(self.rw.workspace_name, result["log"])  # and it says which one it took
        self.assertNotIn("[WARN] Railway does not know", result["log"])

    def test_a_railway_that_wants_a_workspace_gets_the_one_that_is_found(self):
        self.rw.require_workspace = True
        proc, _ = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)

    def test_a_railway_that_wants_a_workspace_and_lists_none_says_how_to_give_it(self):
        self.rw.require_workspace = True
        self.rw.me_shape = ""  # `me` does not say which workspaces there are
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("workspaceId is required", result["log"])
        self.assertIn("RAILWAY_WORKSPACE_ID", result["log"])
        self.assertIn("--railway-workspace", result["log"])
        proc, _ = self.run_script(RAILWAY_WORKSPACE_ID=self.rw.workspace_id)  # and with it, it works
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_the_older_teams_shape_of_me_is_understood_too(self):
        self.rw.me_shape = "teams"
        proc, _ = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)

    # ------------------------------------------------------------ a workspace id that is wrong must not stop the deploy
    def test_a_workspace_id_that_railway_does_not_know_is_ignored(self):
        # what a first-time user ran into: the workspace question was answered with something that is no workspace id
        proc, result = self.run_script(RAILWAY_WORKSPACE_ID="not-a-workspace-id")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[WARN] Railway does not know the workspace 'not-a-workspace-id'", result["log"])
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)  # the right one was found instead
        self.assertTrue(result["ok"])

    def test_a_workspace_token_with_a_wrong_workspace_id_still_deploys(self):
        self.rw.workspace_token = True  # cannot list workspaces: the given id is asked about, and found wrong
        proc, result = self.run_script(RAILWAY_WORKSPACE_ID="nope")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Railway does not know the workspace 'nope'", result["log"])
        self.assertEqual(len(self.rw.projects), 1)

    def test_the_workspace_may_be_given_by_its_name(self):
        self.rw.extra_workspaces = [{"id": "ws-second", "name": "Second Team"}]
        proc, _ = self.run_script(RAILWAY_WORKSPACE_ID="second team")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], "ws-second")

    def test_with_several_workspaces_the_one_that_holds_the_project_is_used_again(self):
        self.rw.extra_workspaces = [{"id": "ws-second", "name": "Second Team"}]
        proc, _ = self.run_script(RAILWAY_WORKSPACE_ID="ws-second")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], "ws-second")
        proc, result = self.run_script()  # nothing given now: the project is found where it is, not made a second time
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.rw.count("projectCreate"), 1)
        self.assertEqual(self.rw.count("serviceCreate"), 1)
        self.assertIn("Second Team", result["log"])

    def test_with_several_workspaces_and_no_project_yet_it_says_which_one_it_took(self):
        self.rw.extra_workspaces = [{"id": "ws-second", "name": "Second Team"}]
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.only_project()["workspaceId"], self.rw.workspace_id)  # the first one the account lists
        self.assertIn("ws-second", result["log"])  # the others are named, so the choice can be changed
        self.assertIn("RAILWAY_WORKSPACE_ID", result["log"])

    def test_check_and_destroy_do_not_trip_over_a_wrong_workspace_id_either(self):
        self.assertEqual(self.run_script()[0].returncode, 0)
        proc, result = self.run_script("check", RAILWAY_WORKSPACE_ID="wrong")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("exists", result["log"])
        proc, _ = self.run_script("destroy", RAILWAY_WORKSPACE_ID="wrong")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.rw.projects, {})

    def test_a_hiccup_of_the_api_is_retried(self):
        self.rw.flaky = 2
        proc, _ = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    # ------------------------------------------------------------ what goes wrong
    def test_a_wrong_token_is_explained(self):
        proc, result = self.run_script(RAILWAY_API_TOKEN="not-the-token")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(result["ok"])
        self.assertIn("Not Authorized", result["log"])
        self.assertIn("Railway token", result["log"])
        self.assertEqual(self.rw.projects, {})

    def test_a_missing_token_is_reported_before_anything_is_called(self):
        proc, result = self.run_script(RAILWAY_API_TOKEN=None)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RAILWAY_API_TOKEN is not set", result["log"])
        self.assertEqual(self.rw.calls, [])

    def test_the_cloudflare_settings_are_not_needed(self):
        proc, _ = self.run_script(CF_API_TOKEN=None, CF_ACCOUNT_ID=None)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_crashed_deployment_shows_its_log_and_fails(self):
        self.rw.deploy_status = "CRASHED"
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("crashed", result["log"])

    def test_a_start_that_exits_is_reported_with_what_it_printed(self):
        # a start command that cannot work: the deployment dies and its own output is shown
        original = fakes.FakeRailway.op_serviceInstanceUpdate

        def broken(world, v):
            original(world, v)
            world.service(v["s"])["startCommand"] = '/bin/sh -c "echo boom-from-the-container; exit 3"'
            return True

        fakes.FakeRailway.op_serviceInstanceUpdate = broken
        self.addCleanup(setattr, fakes.FakeRailway, "op_serviceInstanceUpdate", original)
        proc, result = self.run_script()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("boom-from-the-container", result["log"])
        self.assertIn("crashed", result["log"])

    def test_a_service_that_never_answers_is_reported(self):
        proc, result = self.run_script(CFP_VERIFY_URL="http://127.0.0.1:9/nothing/health")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("does not answer on its health address", result["log"])

    def test_an_unreachable_api_is_reported(self):
        proc, result = self.run_script(RAILWAY_API_BASE="http://127.0.0.1:9/graphql")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot reach the Railway API", result["log"])

    # ------------------------------------------------------------ destroy and check
    def test_destroy_deletes_the_service_and_the_empty_project(self):
        self.assertEqual(self.run_script()[0].returncode, 0)
        proc, result = self.run_script("destroy")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])
        self.assertEqual(self.rw.projects, {})

    def test_destroy_keeps_a_project_that_holds_other_services(self):
        self.assertEqual(self.run_script()[0].returncode, 0)
        project = self.only_project()
        project["services"]["svc-other"] = {"id": "svc-other", "name": "database", "image": "postgres", "variables": {},
                                            "startCommand": "", "region": "", "domains": [], "targetPort": None, "deployments": []}
        proc, result = self.run_script("destroy")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the project was kept", result["log"])
        self.assertEqual(list(self.only_project()["services"]), ["svc-other"])

    def test_destroy_of_something_that_does_not_exist_is_fine(self):
        proc, result = self.run_script("destroy")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("nothing to delete", result["log"])

    def test_check_accepts_the_token_and_changes_nothing(self):
        proc, result = self.run_script("check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the Railway token is accepted", result["log"])
        self.assertIn("'deploy' creates it", result["log"])
        self.assertEqual(self.rw.projects, {})

    def test_check_rejects_a_wrong_token(self):
        proc, _ = self.run_script("check", RAILWAY_API_TOKEN="nope")
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
