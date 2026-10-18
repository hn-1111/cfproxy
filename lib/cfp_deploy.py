#!/usr/bin/env python3
"""Runs on the GitHub runner (see .github/workflows/deploy.yml): puts the tunnel exit on Cloudflare, or takes it down.

  deploy    Worker:  wrangler deploy + the secrets          Pages: create the project, secrets, wrangler pages deploy
  destroy   deletes the Worker / the Pages project
  check     is the Cloudflare token good, and is the account ready for a workers.dev address?

Everything comes in through environment variables (the workflow maps the repository secrets and variables):
  CFP_ACTION CFP_TARGET(worker|pages) CF_API_TOKEN CF_ACCOUNT_ID AUTH_TOKEN WS_PATH WORKER_NAME CUSTOM_DOMAIN ALLOW
  CFP_PUBKEY (public key of your machine) CFP_RESULT_FILE (where the sealed result is written)
Tests redirect CF_API_BASE / CFP_VERIFY_URL to local servers and put a fake `npx` first in PATH.

Hostnames are masked in the Actions log before anything prints them, and the result (host, log) is sealed with YOUR
public key: only your machine can open it, even if the repository is public. Standard library only.
"""
from __future__ import annotations

import base64
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
TARGETS = ("worker", "pages")
RESULT_VERSION = 1
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

    def validate(self) -> None:
        problems = []
        if self.action not in ACTIONS:
            problems.append(f"unknown action '{self.action}'")
        if self.target not in TARGETS:
            problems.append(f"unknown target '{self.target}' (worker or pages)")
        if not self.token:
            problems.append("CF_API_TOKEN is not set (run './cfproxy.sh setup')")
        if not re.fullmatch(r"[0-9a-f]{32}", self.account):
            problems.append("CF_ACCOUNT_ID must be the 32-character account id")
        if not NAME_RE.match(self.name):
            problems.append("WORKER_NAME may only hold lowercase letters, digits and hyphens (max 52)")
        if self.domain and not DOMAIN_RE.match(self.domain):
            problems.append("CUSTOM_DOMAIN is not a hostname")
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


def verify_health(cfg: Config, host: str, attempts: int = 24, pause: float = 5.0) -> dict:
    """Asks the new deployment for <WS_PATH>/health until it answers (a fresh address needs a moment to appear)."""
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
        mask(cfg.auth, cfg.ws_path, cfg.token, cfg.account)
        api = CloudflareApi(cfg)
        if cfg.action == "check":
            check(cfg, api)
        elif cfg.action == "destroy":
            destroy(cfg, api)
        else:
            host = deploy_worker(cfg, api) if cfg.target == "worker" else deploy_pages(cfg, api)
            result["host"] = host
            health = verify_health(cfg, host)
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
