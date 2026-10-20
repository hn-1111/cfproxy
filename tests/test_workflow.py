"""The workflow files: do they match what the client sends and what the code reads, and is the script safe to feed?"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "lib"))

import cfp_gh as gh  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def load(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        text = f.read()
    return yaml.safe_load(text), text


def triggers(doc):
    return doc[True if True in doc else "on"]  # PyYAML reads the key `on` as True


@unittest.skipIf(yaml is None, "PyYAML not installed")
class DeployWorkflow(unittest.TestCase):
    def setUp(self):
        self.doc, self.text = load(gh.WORKFLOW)
        self.steps = self.doc["jobs"]["run"]["steps"]
        self.run_step = next(s for s in self.steps if "run" in s)

    def test_inputs_match_what_the_client_sends(self):
        inputs = triggers(self.doc)["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"action", "target", "request_id"})
        self.assertEqual(inputs["action"]["options"], list(gh.ACTIONS))
        self.assertEqual(inputs["target"]["options"], list(gh.TARGETS))
        self.assertEqual(triggers(self.doc).keys(), {"workflow_dispatch"})  # nothing else can start it
        self.assertIn("request_id", self.doc["run-name"])  # how the client finds its run again

    def test_secrets_and_variables_are_exactly_the_ones_the_client_sends(self):
        secrets = set(re.findall(r"secrets\.([A-Z0-9_]+)", self.text))
        variables = set(re.findall(r"vars\.([A-Z0-9_]+)", self.text))
        self.assertEqual(secrets, set(gh.SECRET_NAMES))
        self.assertEqual(variables, set(gh.VAR_NAMES))
        env = self.run_step["env"]
        for name in secrets:
            self.assertEqual(env[name], "${{ secrets.%s }}" % name)
        for name in variables:
            self.assertEqual(env[name], "${{ vars.%s }}" % name)

    def test_the_run_step_hands_a_result_over(self):
        env = self.run_step["env"]
        upload = next(s for s in self.steps if str(s.get("uses", "")).startswith("actions/upload-artifact"))
        self.assertEqual(upload["with"]["name"], gh.ARTIFACT)
        self.assertEqual(upload["with"]["path"], env["CFP_RESULT_FILE"])
        self.assertEqual(os.path.basename(upload["with"]["path"]), gh.RESULT_NAME)
        self.assertEqual(upload["with"]["retention-days"], 1)
        self.assertEqual(upload["if"], "${{ !cancelled() }}")  # also after a failed run: the log is in the result

    def test_least_privilege_and_no_injection(self):
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        self.assertEqual(self.doc["concurrency"]["cancel-in-progress"], False)
        self.assertNotIn("${{", self.run_step["run"])  # nothing is pasted into the script: inputs use the environment
        for step in self.steps:
            if step.get("uses"):
                self.assertRegex(step["uses"], r"@(v\d+|[0-9a-f]{40})$", step["uses"])
        self.assertNotIn("persist-credentials: true", self.text)
        self.assertNotIn("pull_request", self.text)

    def test_the_script_calls_a_file_that_exists_and_checks_out_only_what_it_needs(self):
        self.assertIn("lib/cfp_deploy.py", self.run_step["run"])
        self.assertTrue(os.path.exists(os.path.join(ROOT, "lib", "cfp_deploy.py")))
        checkout = next(s for s in self.steps if str(s.get("uses", "")).startswith("actions/checkout"))
        self.assertEqual(checkout["with"]["sparse-checkout"].split(), ["lib", "worker", "server"])

    def test_every_setting_the_deploy_script_reads_reaches_it(self):
        with open(os.path.join(ROOT, "lib", "cfp_deploy.py"), encoding="utf-8") as f:
            source = f.read()
        wanted = set(re.findall(r'env\("([A-Z_]+)"', source))
        test_only = {"CF_API_BASE", "RAILWAY_API_BASE", "RAILWAY_IMAGE", "CFP_VERIFY_URL", "CFP_POLL_SECONDS", "CFP_RETRY_SECONDS"}  # tests point these at local servers / a pinned image
        provided = set(self.run_step["env"])
        self.assertEqual(wanted - test_only - provided, set())

    def test_the_files_the_client_pushes_are_all_the_runner_needs(self):
        self.assertEqual(set(gh.DEPLOY_FILES), {
            ".github/workflows/deploy.yml", "worker/index.js", "server/index.mjs", "lib/cfp_deploy.py", "lib/cfp_crypto.py"})
        for rel in gh.DEPLOY_FILES:
            self.assertTrue(os.path.exists(os.path.join(ROOT, *rel.split("/"))), rel)
        with open(os.path.join(ROOT, "lib", "cfp_deploy.py"), encoding="utf-8") as f:
            imported = set(re.findall(r"^import (cfp_\w+)", f.read(), re.M))
        self.assertEqual(imported, {"cfp_crypto"})  # the only module of lib/ the runner script uses


@unittest.skipIf(yaml is None, "PyYAML not installed")
class ScriptArguments(unittest.TestCase):
    """The `run:` script of the workflow, with a stub instead of lib/cfp_deploy.py that prints what it received."""

    def setUp(self):
        doc, _ = load(gh.WORKFLOW)
        self.script = next(s for s in doc["jobs"]["run"]["steps"] if "run" in s)["run"]
        self.tmp = tempfile.mkdtemp(prefix="wf-script-")
        os.makedirs(os.path.join(self.tmp, "lib"))
        with open(os.path.join(self.tmp, "lib", "cfp_deploy.py"), "w") as f:
            f.write("import json, os\nprint('SEEN ' + json.dumps([os.environ['CFP_ACTION'], os.environ['CFP_TARGET']]))\n")
        self.marker = os.path.join(self.tmp, "pwned")

    def run_script(self, action, target="worker"):
        env = {"PATH": os.environ["PATH"], "CFP_RESULT_FILE": os.path.join(self.tmp, "out", "result.bin"),
               "CFP_ACTION": action, "CFP_TARGET": target}
        r = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", self.script], cwd=self.tmp, env=env,
                           capture_output=True, text=True)
        seen = None
        for line in r.stdout.splitlines():
            if line.startswith("SEEN "):
                seen = json.loads(line[5:])
        return r.returncode, seen

    def test_the_valid_inputs_reach_the_script(self):
        for action in gh.ACTIONS:
            for target in gh.TARGETS:
                self.assertEqual(self.run_script(action, target), (0, [action, target]))
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "out")))

    def test_hostile_inputs_never_reach_the_shell(self):
        attempts = [("deploy", f"worker;touch {self.marker}"), (f"$(touch {self.marker})", "worker"),
                    (f"`touch {self.marker}`", "worker"), ("bogus", "worker"), ("deploy", "bogus"),
                    ("deploy", ""), ("", "worker"), ("deploy worker", "worker"), ("*", "worker")]
        for action, target in attempts:
            code, seen = self.run_script(action, target)
            self.assertEqual(code, 2, (action, target))
            self.assertIsNone(seen, (action, target))
        self.assertFalse(os.path.exists(self.marker))


@unittest.skipIf(yaml is None, "PyYAML not installed")
class CiWorkflow(unittest.TestCase):
    def test_ci_runs_the_tests_without_secrets(self):
        doc, text = load("ci.yml")
        self.assertEqual(doc["permissions"], {"contents": "read"})
        self.assertIn("unittest discover -s tests", text)
        self.assertNotIn("${{ secrets", text)  # the comment may say "secrets"; an expression may not
        self.assertIn("pull_request", triggers(doc))


if __name__ == "__main__":
    unittest.main()
