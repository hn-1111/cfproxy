"""Stand-ins for the three services the deploy chain talks to, so the whole chain runs without any account:

  cfproxy.py -> cfp_gh.py -> FAKE GITHUB -> the workflow's own `run:` script -> cfp_deploy.py -> FAKE npx (wrangler)
                                                                                              -> FAKE CLOUDFLARE API

The fake GitHub behaves like GitHub where it matters for the client: secrets only arrive sealed (and are opened with
the repository's key), files are written through the contents API, the run is found again through its run-name,
artifact and log downloads redirect to ANOTHER host that must not receive the token, and the public log hides what
the workflow asked to mask. Dispatching the workflow really runs .github/workflows/deploy.yml: the file the client
pushed is parsed, the env of its `run` step is evaluated from the secrets / variables / inputs the client sent, the
script is executed with bash inside a checkout made from the repository's files, and the result file is "uploaded".
"""
import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import cfp_crypto

try:
    import yaml
except ImportError:  # the tests that need it are skipped
    yaml = None

WORKFLOW_PATH = ".github/workflows/deploy.yml"
EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ---------------------------------------------------------------- the ${{ }} mini evaluator

def lookup(path, ctx):
    cur = ctx
    for part in path.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part, "")
    return cur


def evaluate(text, ctx):
    """${{ a.b }} and ${{ a.b || 'literal' }}: the only forms the workflow uses."""
    def sub(match):
        value = ""
        for operand in match.group(1).split("||"):
            operand = operand.strip()
            value = operand[1:-1] if operand.startswith("'") and operand.endswith("'") else lookup(operand, ctx)
            if value not in ("", None, False):
                return str(value)
        return "" if value in (None, False) else str(value)
    return EXPR.sub(sub, text)


def public_log(raw, secret_values):
    """What the run log of a public repository shows: ::add-mask:: lines are consumed and hide values from then on."""
    masks = {v for v in secret_values if len(v) >= 4}
    out = []
    for line in raw.splitlines():
        if line.startswith("::add-mask::"):
            value = line[len("::add-mask::"):]
            if len(value) >= 4:
                masks.add(value)
            continue
        for m in sorted(masks, key=len, reverse=True):
            line = line.replace(m, "***")
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------- fake Cloudflare (REST API + wrangler)

class FakeCloudflare:
    """The parts of the Cloudflare API that cfp_deploy.py uses, plus a hook the fake wrangler reports to."""

    def __init__(self, token="cf-test-token", account="a" * 32, subdomain="acme"):
        self.token, self.account, self.subdomain = token, account, subdomain
        self.workers = set()
        self.pages = {}              # project name -> {"subdomain": ...}
        self.calls = []              # (method, path)
        self.verify_user_tokens = True
        self.server = None

    def start(self):
        world = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, status, result=None, errors=None):
                body = json.dumps({"success": status < 300, "errors": errors or [], "result": result}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def serve(self, method):
                u = urlparse(self.path)
                path = u.path
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                if path == "/__fake/event":  # the fake wrangler tells us what it created
                    if body["event"] == "pages-created":
                        world.pages[body["name"]] = {"subdomain": f"{body['name']}.pages.dev"}
                    if body["event"] == "worker-deployed":
                        world.workers.add(body["name"])
                    return self.reply(200, {})
                world.calls.append((method, path))
                if self.headers.get("Authorization") != f"Bearer {world.token}":
                    return self.reply(401, errors=[{"code": 1000, "message": "Invalid API Token"}])
                acct = f"/accounts/{world.account}"
                if path == "/user/tokens/verify":
                    if world.verify_user_tokens:
                        return self.reply(200, {"status": "active"})
                    return self.reply(403, errors=[{"message": "not a user token"}])
                if path == f"{acct}/tokens/verify":
                    return self.reply(200, {"status": "active"})
                if path == f"{acct}/workers/subdomain":
                    if method == "GET":
                        if world.subdomain:
                            return self.reply(200, {"subdomain": world.subdomain})
                        return self.reply(404, errors=[{"code": 10007, "message": "workers.api.error.no_subdomain"}])
                    if method == "PUT":
                        world.subdomain = body["subdomain"]
                        return self.reply(200, {"subdomain": world.subdomain})
                m = re.match(rf"^{acct}/pages/projects/([a-z0-9-]+)$", path)
                if m:
                    if method == "GET":
                        project = world.pages.get(m.group(1))
                        return self.reply(200, project) if project else self.reply(404, errors=[{"message": "Project not found"}])
                    if method == "DELETE":
                        return self.reply(200, {}) if world.pages.pop(m.group(1), None) else self.reply(404, errors=[{"message": "Project not found"}])
                m = re.match(rf"^{acct}/workers/scripts/([a-z0-9-]+)$", path)
                if m and method == "DELETE":
                    if m.group(1) in world.workers:
                        world.workers.discard(m.group(1))
                        return self.reply(200, {})
                    return self.reply(404, errors=[{"message": "Script not found"}])
                return self.reply(404, errors=[{"message": f"no route {method} {path}"}])

            do_GET = lambda self: self.serve("GET")
            do_POST = lambda self: self.serve("POST")
            do_PUT = lambda self: self.serve("PUT")
            do_DELETE = lambda self: self.serve("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


FAKE_NPX = r'''#!/usr/bin/env python3
"""A stand-in for `npx --yes wrangler@4 ...`: prints what wrangler prints, records every call."""
import json, os, re, sys, urllib.request

args = sys.argv[1:]
if args[:2] != ["--yes", "wrangler@4"]:
    print("fake npx: unexpected arguments", args, file=sys.stderr)
    sys.exit(97)
args = args[2:]
takes_secret = args[:2] == ["secret", "put"] or args[:2] == ["pages", "secret"]
stdin = sys.stdin.read() if takes_secret else ""
leaked = [n for n in ("AUTH_TOKEN", "WS_PATH", "CF_API_TOKEN", "CF_ACCOUNT_ID") if n in os.environ]
with open(os.environ["FAKE_WRANGLER_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps({"args": args, "stdin": stdin, "leaked_env": leaked,
                        "token_ok": bool(os.environ.get("CLOUDFLARE_API_TOKEN")),
                        "account_ok": bool(os.environ.get("CLOUDFLARE_ACCOUNT_ID"))}) + "\n")

def report(**event):
    req = urllib.request.Request(os.environ["CF_API_BASE"] + "/__fake/event", data=json.dumps(event).encode(),
                                 method="POST", headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()

def option(name):
    return args[args.index(name) + 1] if name in args else ""

if os.environ.get("FAKE_WRANGLER_FAIL") == " ".join(args[:2]) or os.environ.get("FAKE_WRANGLER_FAIL") == args[0]:
    print("✘ [ERROR] A request to the Cloudflare API failed. (code: 10000)", file=sys.stderr)
    sys.exit(1)

sub = os.environ.get("FAKE_SUBDOMAIN", "acme")
if args[0] == "deploy":
    config = open(option("--config"), encoding="utf-8").read()
    name = re.search(r'^name = "([^"]+)"', config, re.M).group(1)
    assert 'main = "../worker/index.js"' in config, config
    report(event="worker-deployed", name=name)
    print("Total Upload: 7.31 KiB / gzip: 2.55 KiB")
    print(f"Deployed {name} triggers (1.02 sec)")
    print(f"  https://{name}.{sub}.workers.dev")
elif args[:2] == ["secret", "put"]:
    print(f"✨ Success! Uploaded secret {args[2]}")
elif args[:3] == ["pages", "project", "create"]:
    report(event="pages-created", name=args[3])
    print(f"✨ Successfully created the '{args[3]}' project.")
elif args[:2] == ["pages", "secret"]:
    print(f"✨ Success! Uploaded secret {args[3]}")
elif args[:2] == ["pages", "deploy"]:
    assert os.path.exists(os.path.join(args[2], "_worker.js")), "no _worker.js in the Pages directory"
    name = option("--project-name")
    print("✨ Success! Uploaded 1 files (1.2 sec)")
    print(f"🌎 Deploying...\n✨ Deployment complete! Take a peek over at https://1a2b3c4d.{name}.pages.dev")
else:
    print("fake wrangler: unknown command", args, file=sys.stderr)
    sys.exit(98)
'''


def install_fake_npx(folder: str) -> str:
    """Puts an executable `npx` into `folder` and returns the path of the call log it writes."""
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "npx")
    with open(path, "w", encoding="utf-8") as f:
        f.write(FAKE_NPX)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return os.path.join(folder, "wrangler-calls.jsonl")


def read_calls(log: str) -> list:
    try:
        with open(log, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except OSError:
        return []


# ---------------------------------------------------------------- fake GitHub

class GitHubWorld:
    def __init__(self, login="alice", repo="alice/cfproxy"):
        self.login, self.repo = login, repo
        self.token = "test-github-token-abc123"
        self.scopes = "repo, workflow"        # None = fine-grained token (no X-OAuth-Scopes header)
        self.exists = False
        self.private = True
        self.default_branch = "main"
        self.files = {}                       # path -> bytes, on the default branch
        self.sk, self.pk = cfp_crypto.generate_keypair()   # the repository's secret-encryption key
        self.key_id = "568250167242549743"
        self.secrets = {}                     # name -> plaintext, opened with the repository key
        self.vars = {}
        self.runs = {}
        self.artifacts = {}
        self.job_logs = {}
        self.blob_requests = []               # (path, headers) of what the "storage host" received
        self.calls = []                       # (method, path)
        self.runner_env = {}                  # extra environment of the runner process (fake Cloudflare, fake npx)
        self.run_delay = 0.15
        self.n = 1000
        self.port = None

    def nid(self):
        self.n += 1
        return self.n

    def workflow(self):
        return yaml.safe_load(self.files[WORKFLOW_PATH].decode("utf-8"))

    # ------------------------------------------------------------ the runner
    def start_run(self, ref, inputs):
        if WORKFLOW_PATH not in self.files:
            return 404, {"message": "Not Found"}
        wf = self.workflow()
        spec = wf[True if True in wf else "on"]["workflow_dispatch"]["inputs"]
        unknown = sorted(set(inputs) - set(spec))
        if unknown:
            return 422, {"message": f"Unexpected inputs provided: {unknown}"}
        merged = {k: str(v.get("default", "")) for k, v in spec.items()}
        merged.update({k: str(v) for k, v in inputs.items()})
        for name, definition in spec.items():
            if definition.get("type") == "choice" and merged[name] not in definition["options"]:
                return 422, {"message": f"Provided value '{merged[name]}' for input '{name}' not in the list of allowed values"}
        ctx = {"secrets": self.secrets, "vars": self.vars, "inputs": merged,
               "github": {"repository": self.repo, "ref_name": ref}}
        run_id = self.nid()
        run = {"id": run_id, "name": wf["name"], "display_title": evaluate(wf["run-name"], ctx), "event": "workflow_dispatch",
               "status": "queued", "conclusion": None, "head_branch": ref, "inputs": merged, "job_id": self.nid(),
               "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "html_url": f"https://github.com/{self.repo}/actions/runs/{run_id}"}
        self.runs[run_id] = run
        threading.Thread(target=self.execute, args=(run, ctx, wf, dict(self.files)), daemon=True).start()
        return 204, None

    def execute(self, run, ctx, wf, snapshot):
        time.sleep(self.run_delay)
        run["status"] = "in_progress"
        time.sleep(self.run_delay)
        steps = wf["jobs"]["run"]["steps"]
        step = next(s for s in steps if "run" in s)
        tmp = tempfile.mkdtemp(prefix="gh-runner-")
        checkout = os.path.join(tmp, "checkout")
        wanted = next((s["with"]["sparse-checkout"].split() for s in steps
                       if str(s.get("uses", "")).startswith("actions/checkout") and "sparse-checkout" in s.get("with", {})), None)
        for rel, data in snapshot.items():  # actions/checkout: only what the sparse-checkout asks for
            if wanted and rel.split("/")[0] not in wanted:
                continue
            target = os.path.join(checkout, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
        ctx["runner"] = {"temp": tmp}
        env = {k: evaluate(str(v), ctx) for k, v in step["env"].items()}
        env.update({"PATH": os.environ["PATH"], "HOME": tmp, "GITHUB_ACTIONS": "true"})
        env.update(self.runner_env)
        proc = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", step["run"]], cwd=checkout, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        run["log"] = proc.stdout
        self.job_logs[run["job_id"]] = public_log(proc.stdout, [v for v in self.secrets.values()])
        result = env.get("CFP_RESULT_FILE", "")
        upload = next((s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact")), None)
        if upload and result and os.path.exists(result):  # actions/upload-artifact: one file, zipped
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.write(result, os.path.basename(result))
            aid = self.nid()
            self.artifacts[aid] = {"id": aid, "run_id": run["id"], "name": upload["with"]["name"],
                                   "zip": buf.getvalue(), "expired": False}
        run["returncode"] = proc.returncode
        run["conclusion"] = "success" if proc.returncode == 0 else "failure"
        run["status"] = "completed"


def start_github(world):
    repo = re.escape(world.repo)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, status, payload=None, headers=None, raw=None, ctype="application/json"):
            body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
            self.send_response(status)
            if body or raw is not None:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def redirect(self, path):
            # a different host name than the API's: like GitHub's storage, and urllib must not send the token there
            self.reply(302, headers={"Location": f"http://localhost:{world.port}{path}"})

        def serve(self, method):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            path = u.path
            if path.startswith("/blob/"):
                world.blob_requests.append((path, dict(self.headers)))
                kind, _, ident = path[len("/blob/"):].partition("/")
                if kind == "artifact":
                    return self.reply(200, raw=world.artifacts[int(ident)]["zip"], ctype="application/zip")
                if kind == "log":
                    return self.reply(200, raw=world.job_logs[int(ident)].encode(), ctype="text/plain")
                return self.reply(404, {"message": "Not Found"})
            world.calls.append((method, path))
            if self.headers.get("Authorization") != f"Bearer {world.token}":
                return self.reply(401, {"message": "Bad credentials"})
            if path == "/user" and method == "GET":
                return self.reply(200, {"login": world.login},
                                  {"X-OAuth-Scopes": world.scopes} if world.scopes is not None else None)
            if path == "/user/repos" and method == "POST":
                if world.exists:
                    return self.reply(422, {"message": "Repository creation failed.", "errors": [{"message": "name already exists"}]})
                world.exists = True
                world.private = bool(body.get("private"))
                world.files = {}
                return self.reply(201, {"full_name": world.repo})
            m = re.match(rf"^/repos/{repo}(/.*)?$", path)
            if not m or not world.exists:
                return self.reply(404, {"message": "Not Found"})
            sub = m.group(1) or ""
            if sub == "" and method == "GET":
                return self.reply(200, {"full_name": world.repo, "private": world.private,
                                        "default_branch": world.default_branch,
                                        "permissions": {"admin": True, "push": True, "pull": True}})
            if sub == "/branches" and method == "GET":
                if not world.files:
                    return self.reply(409, {"message": "Git Repository is empty."})
                return self.reply(200, [{"name": world.default_branch}])
            c = re.match(r"^/contents/(.+)$", sub)
            if c:
                return self.contents(method, c.group(1), q, body)
            return self.actions(method, sub, q, body)

        def contents(self, method, file_path, q, body):
            if method == "GET":
                if not world.files or (q.get("ref") not in (None, world.default_branch)) or file_path not in world.files:
                    return self.reply(404, {"message": "Not Found"})
                return self.reply(200, {"name": os.path.basename(file_path), "path": file_path, "type": "file",
                                        "sha": blob_sha(world.files[file_path])})
            if method == "PUT":
                if not world.files and body.get("branch"):
                    return self.reply(404, {"message": f"Branch {body['branch']} not found"})  # empty repository
                if world.files and body.get("branch") not in (None, world.default_branch):
                    return self.reply(404, {"message": f"Branch {body['branch']} not found"})
                current = world.files.get(file_path)
                if current is not None and not body.get("sha"):
                    return self.reply(422, {"message": "Invalid request.\n\n\"sha\" wasn't supplied."})
                if current is not None and body["sha"] != blob_sha(current):
                    return self.reply(409, {"message": f"{file_path} does not match {body['sha']}"})
                world.files[file_path] = base64.b64decode(body["content"])
                return self.reply(200 if current is not None else 201, {"content": {"path": file_path}})
            return self.reply(404, {"message": "Not Found"})

        def actions(self, method, sub, q, body):
            if sub == "/actions/secrets/public-key" and method == "GET":
                return self.reply(200, {"key_id": world.key_id, "key": base64.b64encode(world.pk).decode()})
            s = re.match(r"^/actions/secrets(?:/([A-Za-z0-9_]+))?$", sub)
            if s:
                name = s.group(1)
                if name is None and method == "GET":
                    names = sorted(world.secrets)
                    page, per = int(q.get("page", 1)), int(q.get("per_page", 30))
                    chunk = names[(page - 1) * per:page * per]
                    return self.reply(200, {"total_count": len(names), "secrets": [{"name": n} for n in chunk]})
                if method == "PUT":
                    if body.get("key_id") != world.key_id:
                        return self.reply(422, {"message": "key_id does not match"})
                    try:
                        value = cfp_crypto.open_sealed(base64.b64decode(body["encrypted_value"]), world.pk, world.sk).decode()
                    except ValueError:
                        return self.reply(422, {"message": "Failed to decrypt the secret"})
                    created = name not in world.secrets
                    world.secrets[name] = value
                    return self.reply(201 if created else 204)
                if method == "DELETE":
                    return self.reply(204) if world.secrets.pop(name, None) is not None else self.reply(404, {"message": "Not Found"})
            v = re.match(r"^/actions/variables(?:/([A-Za-z0-9_]+))?$", sub)
            if v:
                name = v.group(1)
                if name is None and method == "GET":
                    names = sorted(world.vars)
                    page, per = int(q.get("page", 1)), min(int(q.get("per_page", 10)), 30)
                    chunk = names[(page - 1) * per:page * per]
                    return self.reply(200, {"total_count": len(names),
                                            "variables": [{"name": n, "value": world.vars[n]} for n in chunk]})
                if name is None and method == "POST":
                    if body["name"] in world.vars:
                        return self.reply(409, {"message": "Already exists"})
                    world.vars[body["name"]] = body["value"]
                    return self.reply(201)
                if method == "PATCH":
                    if name not in world.vars:
                        return self.reply(404, {"message": "Not Found"})
                    world.vars[name] = body["value"]
                    return self.reply(204)
                if method == "DELETE":
                    return self.reply(204) if world.vars.pop(name, None) is not None else self.reply(404, {"message": "Not Found"})
            if sub == "/actions/workflows/deploy.yml/dispatches" and method == "POST":
                status, payload = world.start_run(body["ref"], body.get("inputs") or {})
                return self.reply(status, payload)
            if sub == "/actions/workflows/deploy.yml/runs" and method == "GET":
                runs = sorted(world.runs.values(), key=lambda r: r["id"], reverse=True)
                return self.reply(200, {"total_count": len(runs), "workflow_runs": [self.public(r) for r in runs]})
            r = re.match(r"^/actions/runs/(\d+)(?:/(jobs|artifacts))?$", sub)
            if r and method == "GET":
                run = world.runs.get(int(r.group(1)))
                if run is None:
                    return self.reply(404, {"message": "Not Found"})
                if r.group(2) is None:
                    return self.reply(200, self.public(run))
                if r.group(2) == "jobs":
                    done = run["status"] == "completed"
                    steps = [{"name": "Run actions/checkout@v4", "status": "completed", "conclusion": "success", "number": 1},
                             {"name": f"cfproxy {run['inputs']['action']}", "number": 2,
                              "status": "completed" if done else ("in_progress" if run["status"] == "in_progress" else "queued"),
                              "conclusion": run["conclusion"] if done else None}]
                    return self.reply(200, {"jobs": [{"id": run["job_id"], "name": run["inputs"]["action"], "status": run["status"],
                                                     "conclusion": run["conclusion"], "steps": steps}]})
                found = [a for a in world.artifacts.values() if a["run_id"] == run["id"] and a["name"] == q.get("name", a["name"])]
                return self.reply(200, {"total_count": len(found), "artifacts": [
                    {"id": a["id"], "name": a["name"], "expired": a["expired"], "size_in_bytes": len(a["zip"])} for a in found]})
            a = re.match(r"^/actions/artifacts/(\d+)/zip$", sub)
            if a and method == "GET":
                return self.redirect(f"/blob/artifact/{a.group(1)}") if int(a.group(1)) in world.artifacts else self.reply(404, {"message": "Not Found"})
            j = re.match(r"^/actions/jobs/(\d+)/logs$", sub)
            if j and method == "GET":
                return self.redirect(f"/blob/log/{j.group(1)}") if int(j.group(1)) in world.job_logs else self.reply(404, {"message": "Not Found"})
            return self.reply(404, {"message": f"no route {method} {sub}"})

        @staticmethod
        def public(run):
            keys = ("id", "name", "display_title", "event", "status", "conclusion", "head_branch", "created_at", "html_url")
            return {k: run[k] for k in keys}

        do_GET = lambda self: self.serve("GET")
        do_POST = lambda self: self.serve("POST")
        do_PUT = lambda self: self.serve("PUT")
        do_PATCH = lambda self: self.serve("PATCH")
        do_DELETE = lambda self: self.serve("DELETE")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    world.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{world.port}"
