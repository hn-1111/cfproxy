"""The single-file client: cfproxy.sh copied ALONE (no lib/, no worker/, no tests/) must work, and from there it
controls your GitHub repository through the API.

  Packed          what is packed inside cfproxy.sh is exactly the sources (`python3 tools/build.py` keeps it so)
  Alone           the file in an empty folder: starts, unpacks once, is reused, refuses damaged or hostile content
  ControlsGitHub  setup -> init -> deploy -> destroy driven through that one file against the fake GitHub
                  (the REAL workflow runs the pushed files; Cloudflare and wrangler are fake)
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import helpers
from helpers import HAVE_NODE, ROOT, TOKEN, WS_PATH, fixtures

sys.path.insert(0, os.path.join(ROOT, "tools"))

import build  # noqa: E402
import cfp_common as common  # noqa: E402
import cfp_gh as gh  # noqa: E402
import fakes  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

SH = os.path.join(ROOT, "cfproxy.sh")
BASH = shutil.which("bash")
ACCOUNT = "b" * 32
CF_TOKEN = "cf-single-file-token"
# what the environment of the person running the tests must not leak into the runs below
PRIVATE_NAMES = ("GITHUB_API_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "CF_API_TOKEN",
                 "CF_ACCOUNT_ID", "WORKER_HOST", "WORKER_NAME", "CUSTOM_DOMAIN", "ALLOW", "AUTH_TOKEN", "WS_PATH",
                 "MTPROTO_SECRET", "SOCKS_USER", "SOCKS_PASS", "PUBLIC_HOST")


def clean_env(home, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CFP_", "CFPROXY_")) and k not in PRIVATE_NAMES}
    env.update({"CFPROXY_HOME": home, "NO_COLOR": "1"})
    env.update(extra)
    return env


def run_sh(path, args, env, cwd=None, timeout=120):
    return subprocess.run([BASH, path, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def read(path):
    with open(path, "rb") as f:
        return f.read()


@unittest.skipIf(BASH is None, "needs bash")
class Packed(unittest.TestCase):
    def test_the_packed_project_is_the_current_sources(self):
        self.assertEqual(build.problems(), [], "cfproxy.sh is out of date: run  python3 tools/build.py")

    def test_what_is_packed(self):
        names = build.payload_names()
        self.assertTrue(set(gh.DEPLOY_FILES) <= set(names))  # what `init` pushes
        self.assertIn("lib/cfproxy.py", names)  # the command line itself
        self.assertEqual([n for n in names if n.startswith(("tests/", "tools/"))], [])
        _, packed = build.read_payload(read(SH))
        self.assertEqual(sorted(packed), sorted(names))

    def test_the_build_does_not_depend_on_the_clock(self):
        self.assertEqual(build.build(), build.build())

    def test_the_data_part_is_only_comments_so_no_shell_can_run_it(self):
        blob = read(SH)
        tail = blob[blob.index(build.MARK):].splitlines()
        self.assertGreater(len(tail), 100)
        self.assertTrue(all(line.startswith(b"#") for line in tail))

    def test_shell_syntax(self):
        r = subprocess.run([BASH, "-n", SH], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        dash = shutil.which("dash")  # the launcher is plain POSIX sh: Alpine / busybox / `sh cfproxy.sh` must work too
        if dash:
            r = subprocess.run([dash, "-n", SH], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_check_notices_a_file_that_is_out_of_date(self):
        tmp = tempfile.mkdtemp(prefix="cfp-stale-")
        self.addCleanup(shutil.rmtree, tmp, True)
        for rel in (*build.payload_names(), build.LAUNCHER, build.OUTPUT):
            target = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy(os.path.join(ROOT, *rel.split("/")), target)
        self.assertEqual(build.problems(tmp), [])
        with open(os.path.join(tmp, "lib", "cfp_common.py"), "ab") as f:
            f.write(b"# changed after the build\n")
        with open(os.path.join(tmp, "lib", "cfp_new.py"), "wb") as f:
            f.write(b"# a new module\n")
        with open(os.path.join(tmp, "tools", "launcher.sh"), "ab") as f:
            f.write(b"# changed too\n")
        found = "\n".join(build.problems(tmp))
        for expected in ("lib/cfp_common.py: differs", "lib/cfp_new.py: not packed", "launcher part differs"):
            self.assertIn(expected, found)

    def test_an_empty_or_missing_file_is_reported_not_crashed_on(self):
        self.assertTrue(build.problems(ROOT, os.path.join(ROOT, "no-such-file.sh")))
        tmp = tempfile.mkdtemp(prefix="cfp-stale-")
        self.addCleanup(shutil.rmtree, tmp, True)
        plain = os.path.join(tmp, "plain.sh")
        with open(plain, "wb") as f:
            f.write(b"#!/bin/sh\necho hi\n")
        self.assertIn("no packed project", build.problems(ROOT, plain)[0])


@unittest.skipIf(BASH is None, "needs bash")
class Alone(unittest.TestCase):
    """cfproxy.sh in a folder where nothing else exists: the situation that used to end in
    "can't open file '.../lib/cfproxy.py'"."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfp-alone-")
        self.home = tempfile.mkdtemp(prefix="cfp-home-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(shutil.rmtree, self.home, True)
        self.sh = os.path.join(self.dir, "cfproxy.sh")
        shutil.copy(SH, self.sh)

    def run_it(self, *args, sh=None, env=None, cwd=None):
        return run_sh(sh or self.sh, args, env or clean_env(self.home), cwd=cwd or self.dir)

    def apps(self):
        base = os.path.join(self.home, "app")
        return sorted(os.listdir(base)) if os.path.isdir(base) else []

    def app_folder(self):
        self.assertEqual(len(self.apps()), 1, self.apps())
        return os.path.join(self.home, "app", self.apps()[0])

    def packed_file(self, name, launcher=None, files=None):
        """A copy of cfproxy.sh with other packed content (to test what happens with a damaged or hostile one)."""
        path = os.path.join(self.dir, name)
        launcher = build.read_source(ROOT, build.LAUNCHER) if launcher is None else launcher
        with open(path, "wb") as f:
            f.write(launcher if files is None else build.assemble(launcher, files))
        return path

    # ------------------------------------------------------------ the case of the report
    def test_it_runs_with_nothing_next_to_it(self):
        self.assertEqual(os.listdir(self.dir), ["cfproxy.sh"])
        r = self.run_it("--version")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, f"cfproxy {common.VERSION}"), r.stderr)
        self.assertEqual(os.listdir(self.dir), ["cfproxy.sh"])  # nothing is written next to the file

    def test_it_runs_from_another_folder_by_a_relative_or_an_absolute_path(self):
        elsewhere = tempfile.mkdtemp(prefix="cfp-cwd-")
        self.addCleanup(shutil.rmtree, elsewhere, True)
        relative = os.path.relpath(self.sh, elsewhere)
        for path in (self.sh, relative):
            r = run_sh(path, ["--version"], clean_env(self.home), cwd=elsewhere)
            self.assertEqual(r.returncode, 0, (path, r.stderr))

    def test_no_arguments_shows_the_help(self):
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("setup", r.stdout)
        self.assertIn("deploy", r.stdout)

    def test_a_symlink_to_it_works(self):
        links = tempfile.mkdtemp(prefix="cfp-links-")
        self.addCleanup(shutil.rmtree, links, True)
        absolute, relative = os.path.join(links, "abs"), os.path.join(links, "rel")
        os.symlink(self.sh, absolute)
        os.symlink(os.path.relpath(self.sh, links), relative)
        for link in (absolute, relative):
            r = self.run_it("--version", sh=link, cwd=links)
            self.assertEqual(r.returncode, 0, (link, r.stderr))
            self.assertEqual(os.listdir(self.dir), ["cfproxy.sh"])

    # ------------------------------------------------------------ the unpacked copy
    def test_it_unpacks_exactly_the_packed_project_into_the_home_folder(self):
        self.assertEqual(self.run_it("--version").returncode, 0)
        app = self.app_folder()
        found = set()
        for folder, dirs, files in os.walk(app):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            found |= {os.path.relpath(os.path.join(folder, f), app).replace(os.sep, "/") for f in files}
        self.assertEqual(found, set(build.payload_names()) | {".complete"})
        for name in build.payload_names():
            self.assertEqual(read(os.path.join(app, *name.split("/"))), read(os.path.join(ROOT, *name.split("/"))), name)

    def test_the_unpacked_folder_holds_what_init_sends_to_github(self):
        self.assertEqual(self.run_it("--version").returncode, 0)
        files = gh.read_deploy_files(self.app_folder())  # the very function `init` uses
        self.assertEqual(set(files), set(gh.DEPLOY_FILES))
        for rel, data in files.items():
            self.assertEqual(data, read(os.path.join(ROOT, *rel.split("/"))), rel)

    def test_the_second_run_reuses_the_unpacked_copy(self):
        self.assertEqual(self.run_it("--version").returncode, 0)
        sentinel = os.path.join(self.app_folder(), "sentinel")
        with open(sentinel, "w") as f:
            f.write("a new unpacking would replace the folder and lose this")
        self.assertEqual(self.run_it("--version").returncode, 0)
        self.assertTrue(os.path.exists(sentinel))
        self.assertEqual(len(self.apps()), 1)

    def test_the_default_folder_is_dot_cfproxy_in_the_home_directory(self):
        fake_home = tempfile.mkdtemp(prefix="cfp-userhome-")
        self.addCleanup(shutil.rmtree, fake_home, True)
        env = clean_env(self.home, HOME=fake_home)
        del env["CFPROXY_HOME"]
        self.assertEqual(self.run_it("--version", env=env).returncode, 0)
        self.assertEqual(len(os.listdir(os.path.join(fake_home, ".cfproxy", "app"))), 1)

    def test_a_half_unpacked_folder_is_replaced(self):
        raw = build.read_zip(read(self.sh))[1]
        stale = os.path.join(self.home, "app", hashlib.sha256(raw).hexdigest()[:12])
        os.makedirs(stale)
        with open(os.path.join(stale, "junk"), "w") as f:
            f.write("left over")
        self.assertEqual(self.run_it("--version").returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(stale, "junk")))
        self.assertTrue(os.path.exists(os.path.join(stale, ".complete")))

    def test_older_versions_are_removed_and_other_folders_are_left_alone(self):
        old, other = (os.path.join(self.home, "app", n) for n in ("0123456789ab", "keep-me"))
        for folder in (old, other):
            os.makedirs(folder)
        self.assertEqual(self.run_it("--version").returncode, 0)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.isdir(other))

    # ------------------------------------------------------------ a project folder next to it
    def test_a_project_folder_next_to_it_is_used_instead(self):
        os.makedirs(os.path.join(self.dir, "lib"))
        with open(os.path.join(self.dir, "lib", "cfproxy.py"), "w") as f:
            f.write("import sys\nprint('FROM-THE-CHECKOUT', sys.argv[1:])\n")
        r = self.run_it("--anything")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "FROM-THE-CHECKOUT ['--anything']"), r.stderr)
        self.assertEqual(self.apps(), [])  # nothing was unpacked

    # ------------------------------------------------------------ what goes wrong is said clearly
    def test_a_file_that_was_cut_short_says_so(self):
        cut = self.packed_file("cut.sh")  # the launcher without the packed project
        r = self.run_it("--version", sh=cut)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not packed", r.stderr)
        self.assertEqual(self.apps(), [])

    def test_a_damaged_payload_says_so(self):
        broken = self.packed_file("broken.sh", files=None)
        with open(broken, "ab") as f:
            f.write(build.MARK + b"\n#bm90IGEgemlwIGZpbGU=\n")  # base64 of "not a zip file"
        r = self.run_it("--version", sh=broken)
        self.assertEqual(r.returncode, 1)
        self.assertIn("damaged", r.stderr)
        self.assertEqual(self.apps(), [])

    def test_a_packed_path_that_leaves_the_folder_is_refused(self):
        for name in ("../evil.txt", "lib/../../evil.txt", "/tmp/cfp-evil-absolute", "..\\evil.txt"):
            hostile = self.packed_file("hostile.sh", files=build.make_zip({"lib/cfproxy.py": b"print('x')", name: b"x"}))
            r = self.run_it("--version", sh=hostile)
            self.assertEqual(r.returncode, 1, name)
            self.assertIn("unsafe path", r.stderr, name)
            self.assertFalse(os.path.exists(os.path.join(self.home, "app", "evil.txt")), name)
            self.assertFalse(os.path.exists(os.path.join(self.home, "evil.txt")), name)
            self.assertFalse(os.path.exists("/tmp/cfp-evil-absolute"), name)
            self.assertEqual(self.apps(), [], name)  # no half-unpacked folder stays behind

    def test_a_home_folder_that_cannot_be_made_is_explained(self):
        blocker = os.path.join(self.home, "a-file")
        with open(blocker, "w") as f:
            f.write("x")
        r = self.run_it("--version", env=clean_env(os.path.join(blocker, "inside")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("CFPROXY_HOME", r.stderr)

    def test_without_python_it_says_what_to_install(self):
        tools = tempfile.mkdtemp(prefix="cfp-nopython-")
        self.addCleanup(shutil.rmtree, tools, True)
        os.symlink(shutil.which("dirname"), os.path.join(tools, "dirname"))  # the one tool the launcher needs besides python
        r = self.run_it("--version", env=clean_env(self.home, PATH=tools))
        self.assertEqual(r.returncode, 127)
        self.assertIn("Python 3.9 or newer", r.stderr)


@unittest.skipIf(BASH is None, "needs bash")
@unittest.skipUnless(HAVE_NODE and yaml is not None, "needs node and PyYAML")
class ControlsGitHub(unittest.TestCase):
    """The reason for the single file: one file on your machine is enough to put the deploy half on GitHub and run it."""

    @classmethod
    def setUpClass(cls):
        cls.plain = fixtures().edge.plain

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfp-alone-")
        self.home = tempfile.mkdtemp(prefix="cfp-home-")
        self.bin = tempfile.mkdtemp(prefix="cfp-bin-")
        for folder in (self.dir, self.home, self.bin):
            self.addCleanup(shutil.rmtree, folder, True)
        self.sh = os.path.join(self.dir, "cfproxy.sh")
        shutil.copy(SH, self.sh)
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
        self.env = clean_env(self.home, GITHUB_API_BASE=github_url, CFP_GH_POLL_SECONDS="0.05",
                             CFP_GH_RETRY_SECONDS="0", CFP_GH_START_TIMEOUT="20")
        # the Worker behind the local edge was started with these two: the .env of this test must hold the same
        env_file = os.path.join(self.home, ".env")
        common.env_set(env_file, "AUTH_TOKEN", TOKEN)
        common.env_set(env_file, "WS_PATH", WS_PATH)

    def cli(self, *args):
        return run_sh(self.sh, args, self.env, cwd=self.dir, timeout=180)

    def dotenv(self):
        with open(os.path.join(self.home, ".env"), encoding="utf-8") as f:
            return common.parse_env_text(f.read())

    def test_setup_init_deploy_destroy_with_only_this_file(self):
        self.assertEqual(os.listdir(self.dir), ["cfproxy.sh"])

        r = self.cli("setup", "--non-interactive", "--github-token", self.world.token, "--repo", "alice/cfproxy",
                     "--cf-token", CF_TOKEN, "--cf-account", ACCOUNT, "--target", "worker", "--allow", "all")
        self.assertEqual(r.returncode, 0, r.stderr)

        # init: the repository is made through the API and gets exactly the files the runner needs
        r = self.cli("init")
        self.assertEqual(r.returncode, 0, r.stderr)
        w = self.world
        self.assertTrue(w.private)
        self.assertEqual(set(w.files), set(gh.DEPLOY_FILES))
        for rel in gh.DEPLOY_FILES:
            self.assertEqual(w.files[rel], read(os.path.join(ROOT, *rel.split("/"))), rel)
        self.assertEqual(w.secrets, {"CF_API_TOKEN": CF_TOKEN, "CF_ACCOUNT_ID": ACCOUNT, "AUTH_TOKEN": TOKEN, "WS_PATH": WS_PATH})
        self.assertEqual(set(w.vars), {"WORKER_NAME", "ALLOW", "CFP_PUBKEY"})

        # init again: nothing to write
        r = self.cli("init")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0 written, 4 already current", r.stderr)

        # deploy: the workflow the client pushed runs on the (fake) runner and the Worker address comes back
        r = self.cli("deploy")
        self.assertEqual(r.returncode, 0, r.stderr)
        env = self.dotenv()
        self.assertEqual(env["WORKER_HOST"], f"{env['WORKER_NAME']}.acme.workers.dev")
        self.assertIn(env["WORKER_NAME"], self.cf.workers)
        self.assertEqual(self.cli("runs").returncode, 0)

        # destroy takes it down again
        r = self.cli("destroy", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(env["WORKER_NAME"], self.cf.workers)
        self.assertEqual(self.dotenv()["WORKER_HOST"], "")

        self.assertEqual(os.listdir(self.dir), ["cfproxy.sh"])  # the whole time nothing but this file was next to it


if __name__ == "__main__":
    unittest.main()
