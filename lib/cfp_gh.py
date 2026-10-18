"""The GitHub half of the client. It talks to GitHub only; Cloudflare is called by the workflow on a GitHub runner
(.github/workflows/deploy.yml -> lib/cfp_deploy.py).

  repository   create it (private by default), push the few files the runner needs, check the token
  settings     keep the repository secrets / variables equal to your .env file (sealed-box encrypted, as GitHub wants)
  runs         start the workflow, wait for it, bring the result back. The result is sealed with YOUR public key:
               nobody else can read it, not even when the repository is public.

Standard library only. GITHUB_API_BASE redirects every call (the tests use a local mock).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import secrets as pysecrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import cfp_crypto as crypto
from cfp_common import USER_AGENT, env, err, info, ok, warn

WORKFLOW = "deploy.yml"
ARTIFACT = "cfproxy-result"
RESULT_NAME = "result.bin"
RESULT_VERSION = 1
ACTIONS = ("deploy", "destroy", "check")
TARGETS = ("worker", "pages")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")

# The only files the runner needs (relative to the project folder). `init` pushes exactly these.
DEPLOY_FILES = (".github/workflows/deploy.yml", "worker/index.js", "lib/cfp_deploy.py", "lib/cfp_crypto.py")

# What `sync` keeps equal to the .env file. The workflow reads exactly these names (tests/test_workflow.py checks it).
SECRET_NAMES = ("CF_API_TOKEN", "CF_ACCOUNT_ID", "AUTH_TOKEN", "WS_PATH", "CUSTOM_DOMAIN")
VAR_NAMES = ("WORKER_NAME", "ALLOW", "CFP_PUBKEY")
REQUIRED_SECRETS = ("CF_API_TOKEN", "CF_ACCOUNT_ID", "AUTH_TOKEN", "WS_PATH")


class GitError(Exception):
    def __init__(self, message: str, status: int = 0, transient: bool = False):
        super().__init__(message)
        self.status = status
        self.transient = transient


def retry(fn, tries: int = 3, base: float = 2.0):
    """fn() with a pause (base, 2*base, ...) after every transient GitError."""
    for attempt in range(tries):
        try:
            return fn()
        except GitError as e:
            if not e.transient or attempt == tries - 1:
                raise
            time.sleep(base * (2 ** attempt))


# ---------------------------------------------------------------- settings

def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def poll_seconds() -> float:
    return float(env("CFP_GH_POLL_SECONDS", "6"))


def github_token() -> str:
    return env("GITHUB_API_TOKEN") or env("GH_TOKEN") or env("GITHUB_TOKEN")


def github_repo() -> str:
    repo = env("GITHUB_REPO")
    if not repo:
        raise GitError("GITHUB_REPO is not set (owner/name of your repository, e.g. alice/cfproxy): run './cfproxy.sh setup'")
    if not REPO_RE.match(repo):
        raise GitError(f"GITHUB_REPO '{repo}' is not valid: use owner/name")
    return repo


def private_key() -> bytes:
    raw = env("CFPROXY_KEY")
    try:
        key = base64.b64decode(raw, validate=True) if raw else b""
    except ValueError:
        key = b""
    if len(key) != crypto.KEY_BYTES:
        raise GitError("CFPROXY_KEY (the key that opens the results) is missing or damaged: run './cfproxy.sh setup'")
    return key


def public_key_b64() -> str:
    return base64.b64encode(crypto.public_key(private_key())).decode()


def blob_sha(data: bytes) -> str:
    """The git blob id of a file: what GitHub reports as `sha`, so unchanged files can be skipped."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ---------------------------------------------------------------- GitHub REST

class _SameHostAuth(urllib.request.HTTPRedirectHandler):
    """Artifact and log downloads redirect to a signed URL on another host: the token must not follow."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            for store in (new.headers, new.unredirected_hdrs):
                for key in [k for k in store if k.lower() == "authorization"]:
                    del store[key]
        return new


def _message(raw: bytes) -> str:
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
        if isinstance(data, dict):
            detail = data.get("message", "")
            if data.get("errors"):
                detail += " " + json.dumps(data["errors"])[:200]
            return detail or "no message"
    except ValueError:
        pass
    return raw.decode("utf-8", "replace")[:200] or "no message"


def hint_for(e: GitError) -> str:
    m = str(e).lower()
    if e.status == 401:
        return "the GitHub token is wrong or expired: create one at github.com/settings/tokens (classic: scopes repo + workflow)"
    if e.status == 403 and "workflow" in m and "scope" in m:
        return "the token needs the 'workflow' scope (fine-grained: Workflows = read and write) to push the workflow file"
    if e.status == 403 and ("rate limit" in m or "abuse" in m):
        return "GitHub rate limit: wait a few minutes and run the command again"
    if e.status == 403:
        return ("the token lacks a permission. Classic token: scopes repo + workflow. Fine-grained token: Actions, "
                "Contents, Secrets, Variables and Workflows = read and write on this repository")
    if e.status == 404:
        return "not found: wrong GITHUB_REPO, or the token has no access to that repository"
    return ""


class GitHub:
    def __init__(self, token: str, repo: str):
        if not token:
            raise GitError("GITHUB_API_TOKEN is not set: create a token at github.com/settings/tokens "
                           "(classic: scopes repo + workflow) and run './cfproxy.sh setup'")
        self.token, self.repo = token, repo
        self.base = (os.environ.get("GITHUB_API_BASE") or "https://api.github.com").rstrip("/")

    def _once(self, method, path, body, params, accept, timeout):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": f"Bearer {self.token}", "Accept": accept, "User-Agent": USER_AGENT,
                   "X-GitHub-Api-Version": "2022-11-28"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.build_opener(_SameHostAuth).open(req, timeout=timeout) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as e:
            raise GitError(f"network error talking to GitHub: {getattr(e, 'reason', e)}", transient=True)

    def call(self, method, path, body=None, params=None, expect=(200, 201, 204),
             accept="application/vnd.github+json", timeout=60.0):
        """(status, raw bytes, headers). Network errors, 5xx and rate limits are retried."""
        def once():
            status, raw, headers = self._once(method, path, body, params, accept, timeout)
            if status in expect:
                return status, raw, headers
            transient = status >= 500 or status == 429 or (status == 403 and bool(headers.get("Retry-After")))
            raise GitError(f"github: HTTP {status}: {_message(raw)}", status, transient)
        return retry(once, tries=3, base=float(env("CFP_GH_RETRY_SECONDS", "2")))

    def json(self, method, path, body=None, params=None, expect=(200, 201, 204)):
        _, raw, _ = self.call(method, path, body, params, expect)
        return json.loads(raw.decode("utf-8")) if raw else None

    def maybe(self, method, path, **kw):
        """json(), but a 404 gives None."""
        try:
            return self.json(method, path, **kw)
        except GitError as e:
            if e.status == 404:
                return None
            raise

    # --- who / where
    def whoami(self):
        _, raw, headers = self.call("GET", "/user")
        scopes = headers.get("X-OAuth-Scopes")  # classic tokens only
        return json.loads(raw)["login"], (None if scopes is None else [s.strip() for s in scopes.split(",") if s.strip()])

    def repo_info(self):
        return self.maybe("GET", f"/repos/{self.repo}")

    def create_repo(self, login: str, private: bool = True) -> dict:
        owner, name = self.repo.split("/")
        body = {"name": name, "description": "cfproxy: a Cloudflare Worker exit for Telegram MTProto / SOCKS5",
                "private": private, "has_issues": False, "has_wiki": False, "has_projects": False, "auto_init": False}
        path = "/user/repos" if owner.lower() == login.lower() else f"/orgs/{owner}/repos"
        return self.json("POST", path, body, expect=(201,))

    def has_commits(self) -> bool:
        try:
            return bool(self.json("GET", f"/repos/{self.repo}/branches", params={"per_page": 1}))
        except GitError as e:
            if e.status in (404, 409):  # "Git Repository is empty."
                return False
            raise

    # --- files
    def get_file(self, path: str, ref: str | None = None):
        params = {"ref": ref} if ref else None
        return self.maybe("GET", f"/repos/{self.repo}/contents/{path}", params=params)

    def put_file(self, path: str, data: bytes, message: str, branch: str | None, sha: str | None) -> None:
        body = {"message": message, "content": base64.b64encode(data).decode()}
        if branch:
            body["branch"] = branch
        if sha:
            body["sha"] = sha
        self.call("PUT", f"/repos/{self.repo}/contents/{path}", body, expect=(200, 201))

    # --- secrets and variables
    def secrets_key(self):
        data = self.json("GET", f"/repos/{self.repo}/actions/secrets/public-key")
        return data["key_id"], base64.b64decode(data["key"])

    def put_secret(self, name: str, value: str, key_id: str, key: bytes) -> None:
        sealed = crypto.seal(value.encode("utf-8"), key)
        self.call("PUT", f"/repos/{self.repo}/actions/secrets/{name}",
                  {"encrypted_value": base64.b64encode(sealed).decode(), "key_id": key_id}, expect=(201, 204))

    def delete_secret(self, name: str) -> None:
        try:
            self.call("DELETE", f"/repos/{self.repo}/actions/secrets/{name}", expect=(204,))
        except GitError as e:
            if e.status != 404:
                raise

    def secret_names(self) -> set:
        names, page = set(), 1
        while True:
            batch = self.json("GET", f"/repos/{self.repo}/actions/secrets", params={"per_page": 100, "page": page}).get("secrets", [])
            names |= {s["name"] for s in batch}
            if len(batch) < 100:
                return names
            page += 1

    def variables(self) -> dict:
        found, page = {}, 1
        while True:
            batch = self.json("GET", f"/repos/{self.repo}/actions/variables", params={"per_page": 30, "page": page}).get("variables", [])
            found.update({v["name"]: v["value"] for v in batch})
            if len(batch) < 30:
                return found
            page += 1

    def set_variable(self, name: str, value: str, exists: bool) -> None:
        if exists:
            self.call("PATCH", f"/repos/{self.repo}/actions/variables/{name}", {"name": name, "value": value}, expect=(204,))
        else:
            self.call("POST", f"/repos/{self.repo}/actions/variables", {"name": name, "value": value}, expect=(201,))

    def delete_variable(self, name: str) -> None:
        try:
            self.call("DELETE", f"/repos/{self.repo}/actions/variables/{name}", expect=(204,))
        except GitError as e:
            if e.status != 404:
                raise

    # --- runs
    def dispatch(self, ref: str, inputs: dict) -> None:
        self.call("POST", f"/repos/{self.repo}/actions/workflows/{WORKFLOW}/dispatches",
                  {"ref": ref, "inputs": inputs}, expect=(200, 204))

    def runs(self, per_page: int = 30) -> list:
        data = self.json("GET", f"/repos/{self.repo}/actions/workflows/{WORKFLOW}/runs",
                         params={"event": "workflow_dispatch", "per_page": per_page})
        return data.get("workflow_runs", [])

    def run(self, run_id) -> dict:
        return self.json("GET", f"/repos/{self.repo}/actions/runs/{run_id}")

    def jobs(self, run_id) -> list:
        return self.json("GET", f"/repos/{self.repo}/actions/runs/{run_id}/jobs").get("jobs", [])

    def artifacts(self, run_id) -> list:
        return self.json("GET", f"/repos/{self.repo}/actions/runs/{run_id}/artifacts", params={"name": ARTIFACT}).get("artifacts", [])

    def download_artifact(self, artifact_id) -> bytes:
        return self.call("GET", f"/repos/{self.repo}/actions/artifacts/{artifact_id}/zip", timeout=120.0)[1]

    def job_log(self, job_id) -> str:
        return self.call("GET", f"/repos/{self.repo}/actions/jobs/{job_id}/logs", timeout=120.0)[1].decode("utf-8", "replace")


def client() -> GitHub:
    return GitHub(github_token(), github_repo())


def default_ref(gh: GitHub) -> str:
    ref = env("GITHUB_BRANCH")
    if ref:
        return ref
    repo = gh.repo_info()
    if repo is None:
        raise GitError(f"repository {gh.repo} not found: wrong GITHUB_REPO, no access, or run './cfproxy.sh init'")
    return repo.get("default_branch") or "main"


# ---------------------------------------------------------------- repository and files

def repo_state(gh: GitHub) -> str:
    """missing | empty | ready (the workflow is there) | occupied (other content, no workflow)"""
    repo = gh.repo_info()
    if repo is None:
        return "missing"
    ref = env("GITHUB_BRANCH") or repo.get("default_branch")
    if gh.get_file(f".github/workflows/{WORKFLOW}", ref) is not None:
        return "ready"
    return "occupied" if gh.has_commits() else "empty"


def read_deploy_files(root: str | None = None) -> dict:
    root = root or project_root()
    files = {}
    for rel in DEPLOY_FILES:
        try:
            with open(os.path.join(root, *rel.split("/")), "rb") as f:
                files[rel] = f.read()
        except OSError as e:
            raise GitError(f"{rel} is missing from the project folder ({e.strerror}): download the project again")
    return files


def push_files(gh: GitHub, root: str | None = None) -> int:
    """Makes the repository hold the current deploy files. Returns how many were written (unchanged ones are skipped)."""
    files = read_deploy_files(root)
    repo = gh.repo_info()
    if repo is None:
        raise GitError(f"repository {gh.repo} not found")
    branch = (env("GITHUB_BRANCH") or repo.get("default_branch") or "main") if gh.has_commits() else env("GITHUB_BRANCH") or None
    written = 0
    for rel, data in files.items():
        current = gh.get_file(rel, branch)
        sha = current.get("sha") if isinstance(current, dict) else None
        if sha == blob_sha(data):
            continue
        gh.put_file(rel, data, f"cfproxy: {'update' if sha else 'add'} {rel}", branch, sha)
        written += 1
        if not branch:  # the very first file made the repository (and its default branch)
            branch = (gh.repo_info() or {}).get("default_branch") or "main"
    return written


# ---------------------------------------------------------------- settings -> repository

def desired_settings() -> tuple:
    """(secrets, variables) built from the environment (the .env file). Empty values are left out."""
    secrets = {n: os.environ[n].strip() for n in SECRET_NAMES if os.environ.get(n, "").strip()}
    variables = {n: os.environ[n].strip() for n in VAR_NAMES if os.environ.get(n, "").strip() and n != "CFP_PUBKEY"}
    variables["CFP_PUBKEY"] = public_key_b64()
    for name, value in {**secrets, **variables}.items():
        if "\n" in value or "\r" in value:
            raise GitError(f"{name} contains a line break: fix it in the .env file")
    missing = [n for n in REQUIRED_SECRETS if n not in secrets]
    if missing:
        raise GitError(f"missing in the .env file: {', '.join(missing)} (run './cfproxy.sh setup')")
    return secrets, variables


def sync(gh: GitHub) -> tuple:
    """Makes the repository secrets / variables equal to the .env file. Returns (sent, changed, removed)."""
    secrets, variables = desired_settings()
    existing_secrets, existing_vars = gh.secret_names(), gh.variables()
    key_id, key = gh.secrets_key()
    sent = changed = removed = 0
    for name in SECRET_NAMES:
        if name in secrets:
            gh.put_secret(name, secrets[name], key_id, key)
            sent += 1
        elif name in existing_secrets:
            gh.delete_secret(name)
            removed += 1
    for name in VAR_NAMES:
        if name in variables:
            if existing_vars.get(name) != variables[name]:
                gh.set_variable(name, variables[name], name in existing_vars)
                changed += 1
        elif name in existing_vars:
            gh.delete_variable(name)
            removed += 1
    return sent, changed, removed


def check(gh: GitHub) -> int:
    """Everything GitHub-side that `deploy` needs. Prints the findings, returns the number of problems."""
    bad = 0
    login, scopes = gh.whoami()
    if scopes is None:
        ok(f"GitHub token works: {login} (fine-grained token)")
    else:
        ok(f"GitHub token works: {login} (scopes: {', '.join(scopes) or 'none'})")
        missing = [s for s in ("repo", "workflow") if s not in scopes]
        if missing:
            bad += 1
            err(f"the classic token lacks the scope(s): {', '.join(missing)}")
    repo = gh.repo_info()
    if repo is None:
        err(f"repository {gh.repo} not found: run './cfproxy.sh init' to create it")
        return bad + 1
    ok(f"repository {gh.repo}: {'private' if repo.get('private') else 'public'}, default branch {repo.get('default_branch')}")
    if repo.get("permissions") and not repo["permissions"].get("push"):
        bad += 1
        err("this token cannot push to the repository: it needs write access")
    ref = env("GITHUB_BRANCH") or repo.get("default_branch")
    if gh.get_file(f".github/workflows/{WORKFLOW}", ref) is None:
        bad += 1
        err(f".github/workflows/{WORKFLOW} not found on {ref}: run './cfproxy.sh init'")
    else:
        ok(f".github/workflows/{WORKFLOW} found on {ref}")
    names, variables = gh.secret_names(), gh.variables()
    absent = [n for n in REQUIRED_SECRETS if n not in names]
    if absent or "CFP_PUBKEY" not in variables:
        bad += 1
        err("the repository settings are not up to date" + (f" (missing secrets: {', '.join(absent)})" if absent else "")
            + ": run './cfproxy.sh init'")
    else:
        ok(f"repository settings: {len(names)} secret(s), {len(variables)} variable(s)")
    return bad


# ---------------------------------------------------------------- running the workflow

def dispatch(gh: GitHub, ref: str, inputs: dict) -> None:
    """Starts the workflow. Right after the first push GitHub needs a few seconds before it knows the workflow:
    while the file is there, a 404 / 'no workflow_dispatch trigger' answer is retried."""
    for attempt in range(6):
        try:
            gh.dispatch(ref, inputs)
            return
        except GitError as e:
            lag = e.status == 404 or (e.status == 422 and "workflow_dispatch" in str(e))
            if lag and attempt < 5 and gh.get_file(f".github/workflows/{WORKFLOW}", ref) is not None:
                time.sleep(poll_seconds())
                continue
            if e.status in (404, 422):
                raise GitError(f"GitHub refused to start .github/workflows/{WORKFLOW} on '{ref}' ({e}). "
                               "Is the project pushed to that branch? (./cfproxy.sh init)", e.status)
            raise


def find_run(gh: GitHub, request_id: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    while True:
        for r in gh.runs():
            if request_id in (r.get("display_title") or "") or request_id in (r.get("name") or ""):
                return r
        if time.time() > deadline:
            raise GitError("GitHub did not start the workflow in time: check the Actions tab of the repository "
                           "(are Actions enabled for it?)")
        time.sleep(poll_seconds())


def current_step(jobs: list) -> str:
    for job in jobs:
        for step in job.get("steps") or []:
            if step.get("status") == "in_progress":
                return step.get("name", "")
        if job.get("status") == "queued":
            return "waiting for a runner"
    return ""


def wait_for(gh: GitHub, run_id, timeout: float) -> dict:
    start, last = time.time(), None
    while True:
        run = gh.run(run_id)
        if run.get("status") == "completed":
            return run
        step = current_step(gh.jobs(run_id)) if run.get("status") == "in_progress" else "waiting for a runner"
        if step and step != last:
            info(f"[{int(time.time() - start)}s] {step}")
            last = step
        if time.time() - start > timeout:
            raise GitError(f"still running after {int(timeout)}s: it continues on GitHub, bring the result later with: "
                           f"./cfproxy.sh fetch {run_id}")
        time.sleep(poll_seconds())


def read_result(zip_bytes: bytes) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            sealed = z.read(RESULT_NAME)
    except (zipfile.BadZipFile, KeyError) as e:
        raise GitError(f"the artifact is not what was expected ({e})")
    sk = private_key()
    try:
        data = json.loads(crypto.open_sealed(sealed, crypto.public_key(sk), sk).decode("utf-8"))
    except crypto.CryptoError:
        raise GitError("the result cannot be opened with CFPROXY_KEY: it was sealed for another key. "
                       "Run './cfproxy.sh init' to send the current key, then run the command again")
    if data.get("v") != RESULT_VERSION:
        raise GitError("the result has a newer format: update this folder (download the project again)")
    return data


def show_job_log(gh: GitHub, run_id, lines: int = 40) -> None:
    """No usable result: show the end of the (masked) log of the run instead."""
    for job in gh.jobs(run_id):
        try:
            text = gh.job_log(job["id"])
        except GitError as e:
            warn(f"could not read the log of the job: {e}")
            continue
        cleaned = []
        for line in text.splitlines():
            line = re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", line)
            if line.startswith(("##[group]", "##[endgroup]")) or not line.strip():
                continue
            cleaned.append(line.replace("##[error]", "[ERROR] "))
        warn(f"log of the job '{job.get('name')}' (the last {min(lines, len(cleaned))} lines):")
        for line in cleaned[-lines:]:
            sys.stderr.write(line + "\n")


def deliver(gh: GitHub, run: dict) -> tuple:
    """Brings the sealed result of a finished run back. Returns (result dict or None, success bool)."""
    run_id, conclusion = run["id"], run.get("conclusion")
    payload = None
    if conclusion != "cancelled":
        art = None
        for attempt in range(6):  # the artifact can show up a few seconds after the run completed
            art = next((a for a in gh.artifacts(run_id) if a.get("name") == ARTIFACT and not a.get("expired")), None)
            if art or attempt == 5:
                break
            time.sleep(poll_seconds())
        if art:
            payload = read_result(gh.download_artifact(art["id"]))
    if payload is None:
        warn("the run returned no result" + (" (it was cancelled)" if conclusion == "cancelled" else ""))
        if conclusion != "cancelled":
            show_job_log(gh, run_id)
    return payload, conclusion == "success" and payload is not None


def run_workflow(gh: GitHub, action: str, target: str = "worker", timeout: float = 1800.0) -> tuple:
    """Start -> wait -> bring the result. Returns (result dict or None, success bool, run)."""
    if action not in ACTIONS:
        raise GitError(f"unknown action '{action}'")
    if target not in TARGETS:
        raise GitError(f"unknown target '{target}' (worker or pages)")
    private_key()  # fail early: without it the result could not be opened
    ref = default_ref(gh)
    request_id = pysecrets.token_hex(4)
    info(f"asking GitHub Actions to run '{action}' ({gh.repo}, {ref})...")
    dispatch(gh, ref, {"action": action, "target": target, "request_id": request_id})
    run = find_run(gh, request_id, float(env("CFP_GH_START_TIMEOUT", "120")))
    info(f"run {run['id']} started: {run.get('html_url', '')}")
    run = wait_for(gh, run["id"], timeout)
    payload, good = deliver(gh, run)
    return payload, good, run
