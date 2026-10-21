#!/usr/bin/env python3
"""Runs on the GitHub runner (see .github/workflows/deploy.yml): puts the tunnel exit on Cloudflare or Railway, or takes it down.

  deploy    Worker:  wrangler deploy + the secrets          Pages: create the project, secrets, wrangler pages deploy
            Railway: project + service from a public Node image, the tunnel code as a variable, a *.up.railway.app domain
  destroy   deletes the Worker / the Pages project / the Railway service (and its project when nothing else is in it)
  check     is the Cloudflare / Railway token good (and is the Cloudflare account ready for a workers.dev address)?

Everything comes in through environment variables (the workflow maps the repository secrets and variables):
  CFP_ACTION CFP_TARGET(worker|pages|railway) CF_API_TOKEN CF_ACCOUNT_ID RAILWAY_API_TOKEN RAILWAY_WORKSPACE_ID RAILWAY_REGION
  AUTH_TOKEN WS_PATH WORKER_NAME CUSTOM_DOMAIN ALLOW
  CFP_PUBKEY (public key of your machine) CFP_RESULT_FILE (where the sealed result is written)
Tests redirect CF_API_BASE / RAILWAY_API_BASE / CFP_VERIFY_URL to local servers and put a fake `npx` first in PATH.

Hostnames are masked in the Actions log before anything prints them, and the result (host, log) is sealed with YOUR
public key: only your machine can open it, even if the repository is public. Standard library only.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfp_crypto as crypto  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRANGLER = ["npx", "--yes", "wrangler@4"]
COMPAT_DATE = "2024-11-01"
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,50}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,100}$")
ACTIONS = ("deploy", "destroy", "check")
TARGETS = ("worker", "pages", "railway")
RESULT_VERSION = 1
RAILWAY_API = "https://backboard.railway.com/graphql/v2"
RAILWAY_IMAGE = "node:22-alpine"  # any public image with Node 18+ and a POSIX shell with base64 and gunzip
RAILWAY_PORT = "8080"
RAILWAY_SERVICE = "edge"
APP_MARKER = "//@@WORKER@@"  # in server/index.mjs: where worker/index.js is pasted
WORKER_IMPORT = 'import { connect } from "cloudflare:sockets";'
WORKER_STUB = 'const connect = () => { throw new Error("cloudflare:sockets is not available here"); };'  # what replaces it
# Railway runs an image's start command in exec form, so the shell is spelled out: only then is $CFP_APP expanded
START_COMMAND = '/bin/sh -c "echo $CFP_APP | base64 -d | gunzip > /tmp/cfp.mjs && exec node /tmp/cfp.mjs"'
FAILED_STATES = ("FAILED", "CRASHED")
POLL_PAUSE = 5.0  # seconds between two looks at a Railway deployment
RETRY_PAUSE = 3.0  # seconds before the Railway API is asked again after a hiccup
LOG: list = []


class DeployError(Exception):
    pass


# ---------------------------------------------------------------- log and masking

def env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value.strip() if value is not None and value.strip() else default


def say(tag: str, text: str) -> None:
    for line in str(text).splitlines() or [""]:
        LOG.append(f"{tag} {line}".rstrip())
        print(f"{tag} {line}".rstrip(), flush=True)


POLL_PAUSE = float(env("CFP_POLL_SECONDS") or POLL_PAUSE)  # tests shorten the waits
RETRY_PAUSE = float(env("CFP_RETRY_SECONDS") or RETRY_PAUSE)


def info(text): say("==>", text)
def ok(text): say("[OK]", text)
def warn(text): say("[WARN]", text)
def err(text): say("[ERROR]", text)


def mask(*values) -> None:
    """GitHub hides these strings in every later line of the log."""
    for value in values:
        if value and "\n" not in value and "\r" not in value:
            print(f"::add-mask::{value}", flush=True)


# ---------------------------------------------------------------- settings

class Config:
    def __init__(self):
        self.action = env("CFP_ACTION", "deploy")
        self.target = env("CFP_TARGET", "worker")
        self.token = env("CF_API_TOKEN")
        self.account = env("CF_ACCOUNT_ID")
        self.auth = env("AUTH_TOKEN")
        self.ws_path = env("WS_PATH", "/ws")
        self.name = env("WORKER_NAME", "cfproxy")
        self.domain = env("CUSTOM_DOMAIN").lower()
        self.allow = env("ALLOW", "all").lower()
        self.pubkey = env("CFP_PUBKEY")
        self.result_file = env("CFP_RESULT_FILE")
        self.api_base = env("CF_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/")
        self.railway_token = env("RAILWAY_API_TOKEN")
        self.railway_workspace = env("RAILWAY_WORKSPACE_ID")
        self.railway_region = env("RAILWAY_REGION")
        self.railway_image = env("RAILWAY_IMAGE", RAILWAY_IMAGE)
        self.railway_base = env("RAILWAY_API_BASE", RAILWAY_API)

    def validate(self) -> None:
        problems = []
        if self.action not in ACTIONS:
            problems.append(f"unknown action '{self.action}'")
        if self.target not in TARGETS:
            problems.append(f"unknown target '{self.target}' (worker, pages or railway)")
        if self.target == "railway":
            if not self.railway_token:
                problems.append("RAILWAY_API_TOKEN is not set (run './cfproxy.sh setup')")
        else:
            if not self.token:
                problems.append("CF_API_TOKEN is not set (run './cfproxy.sh setup')")
            if not re.fullmatch(r"[0-9a-f]{32}", self.account):
                problems.append("CF_ACCOUNT_ID must be the 32-character account id")
            if self.domain and not DOMAIN_RE.match(self.domain):
                problems.append("CUSTOM_DOMAIN is not a hostname")
        if not NAME_RE.match(self.name):
            problems.append("WORKER_NAME may only hold lowercase letters, digits and hyphens (max 52)")
        if self.action == "deploy":
            if not self.auth:
                problems.append("AUTH_TOKEN is not set (run './cfproxy.sh setup')")
            if not PATH_RE.match(self.ws_path):
                problems.append("WS_PATH must start with / and use letters, digits and . _ ~ - /")
            if self.allow not in ("all", "telegram"):
                problems.append("ALLOW must be 'all' or 'telegram'")
        if problems:
            raise DeployError("; ".join(problems))


# ---------------------------------------------------------------- Cloudflare API

class CloudflareApi:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def call(self, method: str, path: str, body=None, ok_404: bool = False):
        """The `result` of a Cloudflare API answer. Raises DeployError (404 gives None when ok_404)."""
        url = self.cfg.api_base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.cfg.token}", "Content-Type": "application/json",
            "User-Agent": "cfproxy-deploy"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            raise DeployError(f"cannot reach the Cloudflare API: {getattr(e, 'reason', e)}")
        try:
            answer = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except ValueError:
            answer = {}
        if status == 404 and ok_404:
            return None
        if status >= 300 or not answer.get("success", status < 300):
            messages = "; ".join(str(e.get("message", e)) for e in (answer.get("errors") or [])) or f"HTTP {status}"
            hint = ""
            if status in (401, 403):
                hint = " (the token is wrong, expired or lacks a permission: see README, 'Cloudflare token')"
            raise DeployError(f"Cloudflare API {method} {path.split('?')[0]}: {messages}{hint}")
        return answer.get("result")

    def verify_token(self) -> str:
        """'active' for a working token. User tokens and account tokens are verified at different addresses."""
        for path in ("/user/tokens/verify", f"/accounts/{self.cfg.account}/tokens/verify"):
            try:
                result = self.call("GET", path)
            except DeployError:
                continue
            if result and result.get("status"):
                return result["status"]
        raise DeployError("the Cloudflare token is not accepted (wrong, expired or revoked)")

    def subdomain(self, create: bool = False):
        """The account's workers.dev subdomain (registered when missing and create=True)."""
        found = None
        try:
            found = self.call("GET", f"/accounts/{self.cfg.account}/workers/subdomain", ok_404=True)
        except DeployError as e:
            if "subdomain" not in str(e).lower() and "10007" not in str(e):
                raise
        if found and found.get("subdomain"):
            return found["subdomain"]
        if not create:
            return None
        wanted = "cfp-" + pysecrets.token_hex(4)
        info("this account has no workers.dev address yet: registering one")
        made = self.call("PUT", f"/accounts/{self.cfg.account}/workers/subdomain", {"subdomain": wanted})
        return (made or {}).get("subdomain") or wanted

    def pages_project(self, name: str):
        return self.call("GET", f"/accounts/{self.cfg.account}/pages/projects/{name}", ok_404=True)


# ---------------------------------------------------------------- wrangler

def wrangler(cfg: Config, args: list, stdin: str | None = None, timeout: int = 600) -> tuple:
    """Runs wrangler. Returns (exit code, output). Secrets only ever travel through stdin, never the command line."""
    environment = dict(os.environ, CLOUDFLARE_API_TOKEN=cfg.token, CLOUDFLARE_ACCOUNT_ID=cfg.account,
                       WRANGLER_SEND_METRICS="false", CI="true", NO_COLOR="1", FORCE_COLOR="0")
    for name in ("AUTH_TOKEN", "WS_PATH", "CF_API_TOKEN", "CF_ACCOUNT_ID"):
        environment.pop(name, None)  # not needed by wrangler: keep them out of its (and its plugins') environment
    try:
        done = subprocess.run(WRANGLER + args, input=stdin, capture_output=True, text=True, timeout=timeout,
                              cwd=ROOT, env=environment)
    except FileNotFoundError:
        raise DeployError("npx is not available on this runner")
    except subprocess.TimeoutExpired:
        raise DeployError("wrangler took too long")
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def show(output: str, limit: int = 40) -> None:
    lines = [ln for ln in output.splitlines() if ln.strip()]
    for line in lines[-limit:]:
        say("   ", line)


def secret_values(cfg: Config) -> list:
    values = [("AUTH_TOKEN", cfg.auth), ("WS_PATH", cfg.ws_path), ("ALLOW", cfg.allow)]
    return [(k, v) for k, v in values if v]


def worker_config(cfg: Config) -> str:
    """build/wrangler.toml: the repository's worker, named WORKER_NAME, on workers.dev (and on CUSTOM_DOMAIN)."""
    folder = os.path.join(ROOT, "build")
    os.makedirs(folder, exist_ok=True)
    lines = [f'name = "{cfg.name}"', 'main = "../worker/index.js"', f'compatibility_date = "{COMPAT_DATE}"',
             "workers_dev = true"]
    if cfg.domain:
        lines.append(f'routes = [{{ pattern = "{cfg.domain}", custom_domain = true }}]')
    path = os.path.join(folder, "wrangler.toml")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def pages_directory() -> str:
    """build/pages/_worker.js: the same file, as a Pages 'advanced mode' worker."""
    folder = os.path.join(ROOT, "build", "pages")
    shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(folder)
    shutil.copyfile(os.path.join(ROOT, "worker", "index.js"), os.path.join(folder, "_worker.js"))
    return folder


HOST_RE = re.compile(r"https://([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:workers|pages)\.dev)\b")


def host_from_output(output: str, name: str, target: str) -> str:
    """The address wrangler printed. A Pages deployment url carries a hash in front: the project's own address
    is what we want."""
    for host in HOST_RE.findall(output):
        if target == "worker" and host.startswith(name + "."):
            return host
        if target == "pages":
            parts = host.split(".")
            return ".".join(parts[-3:]) if len(parts) > 3 else host
    return ""


# ---------------------------------------------------------------- the actions

def deploy_worker(cfg: Config, api: CloudflareApi) -> str:
    subdomain = api.subdomain(create=True)
    host = cfg.domain or f"{cfg.name}.{subdomain}.workers.dev"
    mask(host, f"{cfg.name}.{subdomain}.workers.dev", cfg.domain)
    info("deploying the Worker with wrangler")
    config = worker_config(cfg)
    code, output = wrangler(cfg, ["deploy", "--config", config])
    show(output)
    if code != 0:
        raise DeployError("wrangler deploy failed (see the lines above)")
    for key, value in secret_values(cfg):
        code, output = wrangler(cfg, ["secret", "put", key, "--config", config], stdin=value)
        if code != 0:
            show(output)
            raise DeployError(f"wrangler could not set the secret {key}")
    ok("Worker deployed and its secrets are set")
    return host


def deploy_pages(cfg: Config, api: CloudflareApi) -> str:
    if cfg.domain:
        warn("CUSTOM_DOMAIN is only used for Workers: add a custom domain to a Pages project in the dashboard")
    project = api.pages_project(cfg.name)
    if project is None:
        info("creating the Pages project")
        code, output = wrangler(cfg, ["pages", "project", "create", cfg.name, "--production-branch", "main"])
        if code != 0:
            show(output)
            raise DeployError("wrangler could not create the Pages project")
        project = api.pages_project(cfg.name) or {}
    host = (project or {}).get("subdomain") or f"{cfg.name}.pages.dev"
    mask(host)
    directory = pages_directory()
    # Pages applies secrets to the NEXT deployment: set them first, then deploy
    for key, value in secret_values(cfg):
        code, output = wrangler(cfg, ["pages", "secret", "put", key, "--project-name", cfg.name], stdin=value)
        if code != 0:
            show(output)
            raise DeployError(f"wrangler could not set the Pages secret {key}")
    info("deploying to Pages with wrangler")
    code, output = wrangler(cfg, ["pages", "deploy", directory, "--project-name", cfg.name, "--branch", "main",
                                  "--commit-dirty=true"])
    show(output)
    if code != 0:
        raise DeployError("wrangler pages deploy failed (see the lines above)")
    found = host_from_output(output, cfg.name, "pages")
    if found and found != host:
        mask(found)
    ok("Pages project deployed")
    return host


def verify_health(cfg: Config, host: str, attempts: int = 24, pause: float | None = None) -> dict:
    """Asks the new deployment for <WS_PATH>/health until it answers (a fresh address needs a moment to appear)."""
    pause = POLL_PAUSE if pause is None else pause
    url = env("CFP_VERIFY_URL") or f"https://{host}{cfg.ws_path.rstrip('/')}/health"
    last = "no answer"
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cfproxy-deploy"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read(4096).decode("utf-8", "replace"))
            if body.get("ok") and body.get("configured"):
                return body
            last = "answers, but has no AUTH_TOKEN yet" if body.get("ok") else "answers, but is not the Worker"
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = str(getattr(e, "reason", e))
        if attempt + 1 < attempts:
            time.sleep(pause)
    raise DeployError(f"the new deployment does not answer on its health address ({last})")


def destroy(cfg: Config, api: CloudflareApi) -> None:
    if cfg.target == "worker":
        api.call("DELETE", f"/accounts/{cfg.account}/workers/scripts/{cfg.name}?force=true", ok_404=True)
        ok(f"Worker '{cfg.name}' deleted (or it did not exist)")
    else:
        api.call("DELETE", f"/accounts/{cfg.account}/pages/projects/{cfg.name}", ok_404=True)
        ok(f"Pages project '{cfg.name}' deleted (or it did not exist)")


def check(cfg: Config, api: CloudflareApi) -> None:
    ok(f"the Cloudflare token is {api.verify_token()}")
    subdomain = api.subdomain()
    if subdomain:
        ok("workers.dev address of the account: " + subdomain + ".workers.dev")
        mask(subdomain)
    else:
        warn("the account has no workers.dev address yet: 'deploy' registers one")


# ---------------------------------------------------------------- Railway

def railway_app(root: str = ROOT) -> str:
    """server/index.mjs with the real worker/index.js pasted into it: the one file that runs on Railway."""
    with open(os.path.join(root, "server", "index.mjs"), encoding="utf-8") as f:
        server = f.read()
    with open(os.path.join(root, "worker", "index.js"), encoding="utf-8") as f:
        worker = f.read()
    if server.count(APP_MARKER) != 1:
        raise DeployError(f"server/index.mjs must hold the placeholder {APP_MARKER} exactly once")
    if worker.count(WORKER_IMPORT) != 1:
        raise DeployError("worker/index.js no longer imports connect from cloudflare:sockets: update railway_app()")
    worker = worker.replace(WORKER_IMPORT, WORKER_STUB)
    return server.replace(APP_MARKER, worker)


def railway_app_value(root: str = ROOT) -> str:
    """The app as a service variable: gzip + base64 (about 9 KB), decoded again by START_COMMAND."""
    packed = gzip.compress(railway_app(root).encode("utf-8"), compresslevel=9, mtime=0)
    return base64.b64encode(packed).decode("ascii")


PROJECT_FIELDS = "id name environments { edges { node { id name } } } services { edges { node { id name } } }"


def nodes(connection) -> list:
    return [e["node"] for e in ((connection or {}).get("edges") or []) if isinstance(e, dict) and e.get("node")]


def plain_project(node: dict) -> dict:
    return {"id": node["id"], "name": node.get("name") or "", "environments": nodes(node.get("environments")),
            "services": nodes(node.get("services"))}


class RailwayApi:
    """Railway's public API is GraphQL at one address; every call is a POST."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._workspace: str | None = None  # decided once per run, see workspace_id()

    def call(self, query: str, variables: dict | None = None) -> dict:
        """The `data` of the answer. Raises DeployError carrying Railway's own message."""
        body = json.dumps({"query": query, "variables": variables or {}}).encode()
        status, raw, problem = 0, b"", ""
        for attempt in range(3):
            req = urllib.request.Request(self.cfg.railway_base, data=body, method="POST", headers={
                "Authorization": f"Bearer {self.cfg.railway_token}", "Content-Type": "application/json",
                "User-Agent": "cfproxy-deploy"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    status, raw = resp.status, resp.read()
            except urllib.error.HTTPError as e:
                status, raw = e.code, e.read()
            except (urllib.error.URLError, OSError) as e:
                status, raw, problem = 0, b"", str(getattr(e, "reason", e))
            if status in (0, 429, 502, 503, 504) and attempt < 2:
                time.sleep(RETRY_PAUSE * (attempt + 1))
                continue
            break
        if status == 0:
            raise DeployError(f"cannot reach the Railway API: {problem}")
        try:
            answer = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except ValueError:
            answer = {}
        if not isinstance(answer, dict):
            answer = {}
        errors = answer.get("errors")
        if errors or status >= 300:
            messages = "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in (errors or [])) \
                or f"HTTP {status}"
            hint = ""
            if status in (401, 403) or "not authorized" in messages.lower() or "unauthorized" in messages.lower():
                hint = " (the token is wrong, expired or has no access: see README, 'Railway token')"
            raise DeployError(f"Railway API: {messages}{hint}")
        return answer.get("data") or {}

    def verify_token(self) -> str:
        """What kind of token this is. An account token has `me`, a workspace token does not: listing projects works for both."""
        try:
            me = self.call("query { me { name email } }").get("me") or {}
            return "account token of " + (me.get("name") or me.get("email") or "this account")
        except DeployError:
            pass
        self.call("query { projects { edges { node { id } } } }")
        return "workspace token"

    def workspaces(self) -> list:
        """[{"id", "name"}] of the workspaces an account token can use. Empty for a workspace token (it has no `me`) and when
        Railway does not say. Railway has called them workspaces and (before) teams: both shapes are tried."""
        for query, field in (("query { me { workspaces { id name } } }", "workspaces"),
                             ("query { me { teams { edges { node { id name } } } } }", "teams")):
            try:
                me = self.call(query).get("me") or {}
            except DeployError:
                continue
            value = me.get(field)
            items = nodes(value) if isinstance(value, dict) else (value if isinstance(value, list) else [])
            found = [{"id": str(w["id"]), "name": str(w.get("name") or "")} for w in items if isinstance(w, dict) and w.get("id")]
            if found:
                return found
        return []

    def knows_workspace(self, workspace_id: str) -> bool:
        try:
            return bool(self.call("query($w: String!) { workspace(workspaceId: $w) { id } }", {"w": workspace_id}).get("workspace"))
        except DeployError:
            return False

    def projects_in(self, workspace_id: str) -> list:
        data = self.call("query($w: String!) { workspace(workspaceId: $w) { projects { edges { node { "
                         + PROJECT_FIELDS + " } } } } }", {"w": workspace_id})
        return [plain_project(n) for n in nodes((data.get("workspace") or {}).get("projects"))]

    def workspace_id(self) -> str:
        """The workspace the project lives in ('' = let Railway decide, which is what a workspace token needs). Nobody is
        asked: RAILWAY_WORKSPACE_ID is only a hint, and one that Railway does not know is ignored (with a warning)."""
        if self._workspace is None:
            self._workspace = self.pick_workspace()
        return self._workspace

    def pick_workspace(self) -> str:
        wanted = self.cfg.railway_workspace
        known = self.workspaces()
        if wanted:
            hit = next((w for w in known if w["id"] == wanted), None) or next((w for w in known if w["name"].lower() == wanted.lower()), None)
            if hit:
                return hit["id"]
            if self.knows_workspace(wanted):  # not in the list (a workspace token has none): Railway is asked about this one
                return wanted
            warn(f"Railway does not know the workspace '{wanted}': ignoring RAILWAY_WORKSPACE_ID and finding one by itself")
        if not known:
            return ""
        if len(known) > 1:
            for w in known:  # the project of an earlier run decides, so that deploy, check and destroy all look in the same place
                try:
                    holds = any(p["name"] == self.cfg.name for p in self.projects_in(w["id"]))
                except DeployError:
                    continue
                if holds:
                    info(f"using the Railway workspace '{w['name'] or w['id']}' (it already holds the project '{self.cfg.name}')")
                    return w["id"]
        chosen = known[0]
        text = f"using the Railway workspace '{chosen['name'] or chosen['id']}'"
        if len(known) > 1:
            more = ", ".join(f"'{w['name'] or w['id']}' = {w['id']}" for w in known[1:])
            text += f" (the account has more: {more}; to use another one set RAILWAY_WORKSPACE_ID)"
        info(text)
        return chosen["id"]

    def projects(self) -> list:
        workspace = self.workspace_id()
        if workspace:
            try:
                return self.projects_in(workspace)
            except DeployError as e:
                warn(f"cannot list the projects of the Railway workspace ({e}): trying the account's own list instead")
        data = self.call("query { projects { edges { node { " + PROJECT_FIELDS + " } } } }")
        return [plain_project(n) for n in nodes(data.get("projects"))]

    def project(self, project_id: str) -> dict:
        data = self.call("query($id: String!) { project(id: $id) { " + PROJECT_FIELDS + " } }", {"id": project_id})
        if not data.get("project"):
            raise DeployError("Railway does not know the project")
        return plain_project(data["project"])

    def create_project(self, name: str) -> dict:
        payload = {"name": name}
        workspace = self.workspace_id()
        if workspace:
            payload["workspaceId"] = workspace
        data = self.call("mutation($input: ProjectCreateInput!) { projectCreate(input: $input) { id } }", {"input": payload})
        return self.project(data["projectCreate"]["id"])

    def create_service(self, project_id: str, name: str, image: str, variables: dict) -> str:
        data = self.call("mutation($input: ServiceCreateInput!) { serviceCreate(input: $input) { id } }", {"input": {
            "projectId": project_id, "name": name, "source": {"image": image}, "variables": variables}})
        return data["serviceCreate"]["id"]

    def set_variables(self, project_id: str, environment_id: str, service_id: str, variables: dict) -> None:
        self.call("mutation($input: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $input) }", {"input": {
            "projectId": project_id, "environmentId": environment_id, "serviceId": service_id,
            "variables": variables, "skipDeploys": True}})

    def configure(self, service_id: str, environment_id: str, region: str = "") -> None:
        settings = {"startCommand": START_COMMAND, "sleepApplication": False}
        if region:
            settings["region"] = region
        self.call("mutation($s: String!, $e: String!, $input: ServiceInstanceUpdateInput!) { "
                  "serviceInstanceUpdate(serviceId: $s, environmentId: $e, input: $input) }",
                  {"s": service_id, "e": environment_id, "input": settings})

    def domains(self, project_id: str, environment_id: str, service_id: str) -> list:
        data = self.call("query($p: String!, $e: String!, $s: String!) { domains(projectId: $p, environmentId: $e, "
                         "serviceId: $s) { serviceDomains { domain } } }", {"p": project_id, "e": environment_id, "s": service_id})
        found = ((data.get("domains") or {}).get("serviceDomains")) or []
        return [d["domain"] for d in found if isinstance(d, dict) and d.get("domain")]

    def create_domain(self, service_id: str, environment_id: str, port: str) -> str:
        data = self.call("mutation($input: ServiceDomainCreateInput!) { serviceDomainCreate(input: $input) { domain } }", {
            "input": {"serviceId": service_id, "environmentId": environment_id, "targetPort": int(port)}})
        return data["serviceDomainCreate"]["domain"]

    def trigger(self, service_id: str, environment_id: str) -> None:
        self.call("mutation($s: String!, $e: String!) { serviceInstanceDeploy(serviceId: $s, environmentId: $e) }",
                  {"s": service_id, "e": environment_id})

    def deployments(self, project_id: str, service_id: str) -> list:
        data = self.call("query($input: DeploymentListInput!) { deployments(input: $input, first: 10) { edges { node { "
                         "id status createdAt } } } }", {"input": {"projectId": project_id, "serviceId": service_id}})
        return nodes(data.get("deployments"))

    def logs(self, deployment_id: str, limit: int = 40) -> list:
        data = self.call("query($d: String!, $n: Int) { deploymentLogs(deploymentId: $d, limit: $n) { message } }",
                         {"d": deployment_id, "n": limit})
        return [str(x.get("message", "")) for x in (data.get("deploymentLogs") or []) if isinstance(x, dict)]

    def delete_service(self, service_id: str) -> None:
        self.call("mutation($id: String!) { serviceDelete(id: $id) }", {"id": service_id})

    def delete_project(self, project_id: str) -> None:
        self.call("mutation($id: String!) { projectDelete(id: $id) }", {"id": project_id})


def wait_deployment(api: RailwayApi, project_id: str, service_id: str, before: set, timeout: float = 600.0) -> None:
    """Follows the deployment this run started (one that did not exist in `before`) until it is running."""
    deadline = time.monotonic() + timeout
    current, last = None, ""
    while time.monotonic() < deadline:
        fresh = [d for d in api.deployments(project_id, service_id) if d.get("id") not in before]
        if fresh:
            current = sorted(fresh, key=lambda d: str(d.get("createdAt") or ""))[-1]
            state = str(current.get("status") or "").upper()
            if state != last:
                info(f"deployment: {state.lower() or 'unknown'}")
                last = state
            if state == "SUCCESS":
                return
            if state in FAILED_STATES:
                show("\n".join(api.logs(current["id"])))
                raise DeployError(f"the Railway deployment {state.lower()} (see the lines above)")
        time.sleep(POLL_PAUSE)
    raise DeployError("the Railway deployment did not finish in time" if current else "Railway did not start a deployment")


def deploy_railway(cfg: Config, api: RailwayApi) -> str:
    if cfg.domain:
        warn("CUSTOM_DOMAIN is not used with Railway: the service gets a *.up.railway.app address")
    ok(f"the Railway token is accepted ({api.verify_token()})")
    project = next((p for p in api.projects() if p["name"] == cfg.name), None)
    if project is None:
        info(f"creating the Railway project '{cfg.name}'")
        try:
            project = api.create_project(cfg.name)
        except DeployError as e:
            if "workspace" in str(e).lower() and not api.workspace_id():
                raise DeployError(f"{e} (no Railway workspace could be found by itself: set RAILWAY_WORKSPACE_ID, "
                                  "i.e. run './cfproxy.sh setup --railway-workspace <id>')")
            raise
    environment = next((e for e in project["environments"] if e.get("name") == "production"), None) \
        or (project["environments"][0] if project["environments"] else None)
    if environment is None:
        raise DeployError("the Railway project has no environment")
    variables = {"AUTH_TOKEN": cfg.auth, "WS_PATH": cfg.ws_path, "ALLOW": cfg.allow, "PORT": RAILWAY_PORT,
                 "CFP_APP": railway_app_value()}
    service = next((s for s in project["services"] if s["name"] == RAILWAY_SERVICE), None)
    if service is None:
        info(f"creating the service '{RAILWAY_SERVICE}' from {cfg.railway_image} (the tunnel code travels as a variable)")
        service_id = api.create_service(project["id"], RAILWAY_SERVICE, cfg.railway_image, variables)
    else:
        service_id = service["id"]
    api.set_variables(project["id"], environment["id"], service_id, variables)
    api.configure(service_id, environment["id"], cfg.railway_region)
    domains = api.domains(project["id"], environment["id"], service_id)
    host = domains[0] if domains else api.create_domain(service_id, environment["id"], RAILWAY_PORT)
    mask(host)
    before = {d.get("id") for d in api.deployments(project["id"], service_id)}
    info("starting the deployment")
    api.trigger(service_id, environment["id"])
    wait_deployment(api, project["id"], service_id, before)
    ok("the service is running on Railway")
    return host


def destroy_railway(cfg: Config, api: RailwayApi) -> None:
    project = next((p for p in api.projects() if p["name"] == cfg.name), None)
    if project is None:
        ok(f"Railway project '{cfg.name}' does not exist: nothing to delete")
        return
    service = next((s for s in project["services"] if s["name"] == RAILWAY_SERVICE), None)
    if service is not None:
        api.delete_service(service["id"])
        ok(f"service '{RAILWAY_SERVICE}' deleted")
    left = [s for s in api.project(project["id"])["services"] if s["id"] != (service or {}).get("id")]
    if left:
        warn(f"project '{cfg.name}' still holds {len(left)} other service(s): the project was kept")
    else:
        api.delete_project(project["id"])
        ok(f"the (now empty) project '{cfg.name}' was deleted")


def check_railway(cfg: Config, api: RailwayApi) -> None:
    ok(f"the Railway token is accepted ({api.verify_token()})")
    project = next((p for p in api.projects() if p["name"] == cfg.name), None)
    if project is None:
        info(f"no Railway project '{cfg.name}' yet: 'deploy' creates it")
    else:
        ok(f"Railway project '{cfg.name}' exists ({len(project['services'])} service(s))")
    info("a Railway account that is not verified (Trial) cannot open outbound connections: verify it at railway.com/verify or use the Hobby plan")


# ---------------------------------------------------------------- result

def write_result(cfg: Config, data: dict) -> None:
    """Sealed with the client's public key: only the owner of the matching private key can read it."""
    if not cfg.result_file:
        return
    try:
        key = base64.b64decode(cfg.pubkey, validate=True) if cfg.pubkey else b""
    except ValueError:
        key = b""
    if len(key) != crypto.KEY_BYTES:
        warn("CFP_PUBKEY is missing or damaged: no result for the client (run './cfproxy.sh setup')")
        return
    data = dict(data, v=RESULT_VERSION, log="\n".join(LOG))
    os.makedirs(os.path.dirname(cfg.result_file) or ".", exist_ok=True)
    with open(cfg.result_file, "wb") as f:
        f.write(crypto.seal(json.dumps(data).encode("utf-8"), key))


def main() -> int:
    cfg = Config()
    result = {"ok": False, "action": cfg.action, "target": cfg.target, "name": cfg.name, "host": ""}
    try:
        cfg.validate()
        mask(cfg.auth, cfg.ws_path, cfg.token, cfg.account, cfg.railway_token)
        railway = cfg.target == "railway"
        api = RailwayApi(cfg) if railway else CloudflareApi(cfg)
        if cfg.action == "check":
            (check_railway if railway else check)(cfg, api)
        elif cfg.action == "destroy":
            (destroy_railway if railway else destroy)(cfg, api)
        else:
            if railway:
                host = deploy_railway(cfg, api)
            else:
                host = deploy_worker(cfg, api) if cfg.target == "worker" else deploy_pages(cfg, api)
            result["host"] = host
            health = verify_health(cfg, host, attempts=60 if railway else 24)
            result["colo"] = health.get("colo") or ""
            ok("the deployment answers on its health address")
        result["ok"] = True
    except DeployError as e:
        err(str(e))
    except Exception as e:  # never leave without a result: the client shows the log
        err(f"unexpected error: {type(e).__name__}: {e}")
    write_result(cfg, result)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
