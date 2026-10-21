#!/usr/bin/env python3
"""cfproxy: Telegram MTProto / SOCKS5 proxies that exit through a Cloudflare Worker (or Pages, or Railway) you deploy yourself.

  setup     ask for the tokens, make the secrets (AUTH_TOKEN, MTPROTO_SECRET, ...) and write the .env file
  init      create the GitHub repository, push the deploy files, send the settings to it
  deploy    run the workflow: it puts the Worker (or Pages project, or Railway service) online; WORKER_HOST is saved
  destroy   take it down again
  check     is everything ready? (--remote also checks the Cloudflare / Railway token on the runner)
  status    your settings, the last scan, and whether the deployment answers
  scan      test Cloudflare IPs x ports (Railway: the addresses of your domain) from YOUR network, keep the ones that carry a tunnel
  serve     run the local MTProto + SOCKS5 proxies (they use the scan result)
  links     print the proxy links (tg://proxy, tg://socks, ...)
  test      prove the whole path again: clean IP -> Cloudflare -> Worker -> Telegram
  fetch     bring back the result of a workflow run that was started earlier
  runs      the latest workflow runs

Everything is configured through ~/.cfproxy/.env (CFPROXY_HOME changes the folder). Standard library only.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import os
import re
import secrets
import signal
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cfp_crypto as crypto  # noqa: E402
import cfp_gh as gh_mod  # noqa: E402
import cfp_mtproto as mt  # noqa: E402
import cfp_scan as scan_mod  # noqa: E402
from cfp_bridge import Bridge  # noqa: E402
from cfp_common import (ALL_PORTS, TLS_PORTS, VERSION, ConfigError, Settings, bold, dim, endpoints_path, env,  # noqa: E402
                        env_file, env_set, err, home, info, load_endpoints, load_env, mtproto_links, ok, parse_ports,
                        save_endpoints, say, socks_links, warn)
from cfp_deploy import DOMAIN_RE, NAME_RE  # noqa: E402
from cfp_tunnel import Endpoint, EndpointPool, Tunnel, TunnelError, TunnelRefused  # noqa: E402

LOOPBACK = ("127.0.0.1", "localhost", "::1")
EXIT_IP_TARGET = ("checkip.amazonaws.com", 80)  # not behind Cloudflare (a Worker cannot connect() to Cloudflare IPs)


# ---------------------------------------------------------------- small helpers

def paint(line: str) -> str:
    if not (sys.stderr.isatty() and not os.environ.get("NO_COLOR")):
        return line
    for tag, code in (("[OK]", "32"), ("[WARN]", "33"), ("[ERROR]", "31"), ("==>", "36")):
        if line.startswith(tag):
            return f"\033[{code}m{tag}\033[0m{line[len(tag):]}"
    return line


def lan_ip() -> str:
    """The address of this machine on the local network (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ask(label: str, default: str = "", secret: bool = False, required: bool = True) -> str:
    shown = ""
    if default:
        shown = " [Enter = keep the current one]" if secret else f" [{default}]"
    elif not required:
        shown = " [optional]"
    sys.stderr.write(f"  {label}{shown}: ")
    sys.stderr.flush()
    try:
        raw = getpass.getpass("", stream=sys.stderr) if secret else input()
    except EOFError:
        raw = ""
    return raw.strip() or default


def generate_missing() -> list:
    """The secrets are made once and kept in the .env file."""
    path, made = env_file(), []

    def need(name, make):
        if not env(name):
            env_set(path, name, make())
            made.append(name)

    need("AUTH_TOKEN", lambda: secrets.token_urlsafe(32))
    need("WS_PATH", lambda: "/" + secrets.token_hex(8))
    need("MTPROTO_SECRET", lambda: secrets.token_hex(16))
    need("SOCKS_USER", lambda: "u" + secrets.token_hex(3))
    need("SOCKS_PASS", lambda: secrets.token_urlsafe(12))
    need("WORKER_NAME", lambda: "cfproxy-" + secrets.token_hex(3))
    need("CFPROXY_KEY", lambda: base64.b64encode(crypto.generate_keypair()[0]).decode())
    return made


def best_effort_login(token: str) -> str:
    try:
        return gh_mod.GitHub(token, "x/x").whoami()[0]
    except Exception:  # noqa: BLE001 (offline, bad token: the question is simply asked without a suggestion)
        return ""


def settings(*need: str) -> Settings:
    st = Settings.from_env()
    st.require(*need)
    return st


def load_pool_data(args) -> tuple:
    path = getattr(args, "endpoints", None) or None
    return load_endpoints(path)


# ---------------------------------------------------------------- setup

def v_repo(x):
    return "" if gh_mod.REPO_RE.match(x) else "use owner/name, e.g. alice/cfproxy"


def v_account(x):
    return "" if re.fullmatch(r"[0-9a-fA-F]{32}", x) else "the account id is 32 hex characters (Cloudflare dashboard > Workers & Pages)"


def v_name(x):
    return "" if NAME_RE.match(x) else "only lowercase letters, digits and hyphens (max 52)"


def v_domain(x):
    return "" if not x or DOMAIN_RE.match(x.lower()) else "that is not a hostname"


def v_choice(*options):
    return lambda x: "" if x in options else "choose one of: " + ", ".join(options)


def v_any(x):
    return ""


RAILWAY_NOTICE = ("Railway's Acceptable Use Policy lists 'operating proxies or anonymization services' as abuse: the workspace "
                  "can be restricted or banned. Ask Railway first and use a separate account (README: Railway).")

# (env name, flag attribute, question, secret, required, validator, default, group)
# group: "" always asked | "cf" only for the Cloudflare targets (worker, pages) | "rw" only for railway
#        | "rwx" railway, but never asked: the deploy finds it by itself; only the flag sets it (--railway-workspace ID, "" clears)
SETUP_FIELDS = (
    ("GITHUB_API_TOKEN", "github_token", "GitHub token (classic: scopes repo + workflow)", True, True, v_any, "", ""),
    ("GITHUB_REPO", "repo", "GitHub repository to use (owner/name; it is created when missing)", False, True, v_repo, "", ""),
    ("CFP_TARGET", "target", "Deploy as 'worker' or 'pages' (Cloudflare), or 'railway'", False, True,
     v_choice("worker", "pages", "railway"), "worker", ""),
    ("CF_API_TOKEN", "cf_token", "Cloudflare API token (Edit Cloudflare Workers; Pages: Edit too)", True, True, v_any, "", "cf"),
    ("CF_ACCOUNT_ID", "cf_account", "Cloudflare account id (32 characters)", False, True, v_account, "", "cf"),
    ("RAILWAY_API_TOKEN", "railway_token", "Railway API token (railway.com/account/tokens, workspace: No workspace)", True, True,
     v_any, "", "rw"),
    ("RAILWAY_WORKSPACE_ID", "railway_workspace", "Railway workspace id (not asked: the deploy finds the workspace by itself)", False,
     False, v_any, "", "rwx"),
    ("RAILWAY_REGION", "railway_region", "Railway region (optional, e.g. europe-west4-drams3a; Enter = Railway's default)", False,
     False, v_any, "", "rw"),
    ("ALLOW", "allow", "Exit allowed to: 'all' (SOCKS5 + MTProto) or 'telegram' (MTProto only)", False, True,
     v_choice("all", "telegram"), "all", ""),
    ("CUSTOM_DOMAIN", "domain", "Your own domain on Cloudflare for the Worker", False, False, v_domain, "", "cf"),
)


def cmd_setup(args) -> int:
    path = env_file()
    interactive = sys.stdin.isatty() and not args.non_interactive
    if interactive:
        say(bold("cfproxy setup") + dim(f"   (saved in {path}; Enter keeps what is already there)"))
    target = getattr(args, "target", None) or env("CFP_TARGET") or "worker"
    for name, attr, question, secret, required, validate, default, group in SETUP_FIELDS:
        if (group == "cf" and target == "railway") or (group in ("rw", "rwx") and target != "railway"):
            continue
        current = env(name)
        value = getattr(args, attr, None)
        if value is None and group == "rwx":
            continue  # never asked: what is saved stays as it is
        if value is None:
            if not interactive:
                value = current or default
            else:
                suggestion = current or default
                if name == "GITHUB_REPO" and not suggestion and env("GITHUB_API_TOKEN"):
                    login = best_effort_login(env("GITHUB_API_TOKEN"))
                    suggestion = f"{login}/cfproxy" if login else ""
                value = ask(question, suggestion, secret, required)
        value = value.strip()
        if not value and not required:
            if current:
                env_set(path, name, "")
            continue
        problem = "is required" if not value else validate(value)
        if problem:
            raise ConfigError(f"{name}: {problem}")
        if value != current:
            env_set(path, name, value)
        if name == "CFP_TARGET":
            target = value
            if target == "railway":
                warn(RAILWAY_NOTICE)
    made = generate_missing()
    if made:
        ok("made and saved: " + ", ".join(made))
    ok(f"settings saved in {path}")
    say("Next: ./cfproxy.sh deploy     (then: ./cfproxy.sh scan   and   ./cfproxy.sh serve)")
    return 0


# ---------------------------------------------------------------- GitHub side: init, deploy, destroy, check

def prepare(gh, private: bool = True) -> None:
    """The repository exists, holds the current deploy files and has the current settings."""
    generate_missing()
    login, _ = gh.whoami()
    state = gh_mod.repo_state(gh)
    if state == "missing":
        gh.create_repo(login, private=private)
        ok(f"created the {'private' if private else 'public'} repository {gh.repo}")
    elif state == "occupied":
        warn(f"{gh.repo} already holds other files: only the {len(gh_mod.DEPLOY_FILES)} deploy files are added")
    written = gh_mod.push_files(gh)
    ok(f"deploy files: {written} written, {len(gh_mod.DEPLOY_FILES) - written} already current")
    sent, changed, removed = gh_mod.sync(gh)
    ok(f"repository settings are up to date ({sent} secret(s) sent, {changed} variable(s) changed, {removed} removed)")


def cmd_init(args) -> int:
    prepare(gh_mod.client(), private=not args.public)
    say("Next: ./cfproxy.sh deploy")
    return 0


def apply_result(data: dict, verbose: bool) -> None:
    for line in (data.get("log") or "").splitlines():
        if not verbose and line.startswith("    "):
            continue  # wrangler's own output
        sys.stderr.write(paint(line) + "\n")
    sys.stderr.flush()
    if not data.get("ok"):
        return
    if data.get("action") == "deploy" and data.get("host"):
        env_set(env_file(), "WORKER_HOST", data["host"])
        ok(f"WORKER_HOST={data['host']} saved in {env_file()}")
    elif data.get("action") == "destroy":
        env_set(env_file(), "WORKER_HOST", "")
        ok("WORKER_HOST cleared")


def run_action(action: str, target: str, args) -> int:
    gh = gh_mod.client()
    if action != "destroy":
        prepare(gh, private=True)
    payload, good, run = gh_mod.run_workflow(gh, action, target, float(args.timeout))
    if payload is not None:
        apply_result(payload, args.verbose)
    if good and payload.get("ok"):
        ok(f"GitHub run {run['id']} finished")
        return 0
    err(f"GitHub run {run['id']} {run.get('conclusion') or 'did not finish'}: {run.get('html_url', '')}")
    return 1


def cmd_deploy(args) -> int:
    target = args.target or env("CFP_TARGET", "worker")
    if target == "railway":
        warn(RAILWAY_NOTICE)
    code = run_action("deploy", target, args)
    if code == 0:
        say("Next: ./cfproxy.sh scan     then: ./cfproxy.sh serve")
    return code


def cmd_destroy(args) -> int:
    target = args.target or env("CFP_TARGET", "worker")
    if not args.yes:
        if not sys.stdin.isatty():
            raise ConfigError("destroy asks for a confirmation: run it in a terminal or add --yes")
        what = (f"Delete the Railway service of project '{env('WORKER_NAME', 'cfproxy')}'?" if target == "railway"
                else f"Delete the {target} '{env('WORKER_NAME', 'cfproxy')}' from Cloudflare?")
        if ask(f"{what} Type yes", "", required=False) != "yes":
            warn("nothing deleted")
            return 1
    return run_action("destroy", target, args)


def cmd_check(args) -> int:
    gh = gh_mod.client()
    bad = gh_mod.check(gh)
    if args.cloudflare:
        payload, good, run = gh_mod.run_workflow(gh, "check", env("CFP_TARGET", "worker"), 600.0)
        if payload is not None:
            apply_result(payload, False)
        bad += 0 if good and payload.get("ok") else 1
    elif not bad:
        say("Add --remote to also check the Cloudflare / Railway token (it runs on the GitHub runner).")
    return 1 if bad else 0


def cmd_fetch(args) -> int:
    gh = gh_mod.client()
    if args.run_id:
        run = gh.run(args.run_id)
    else:
        run = next((r for r in gh.runs() if r.get("status") == "completed"), None)
        if run is None:
            raise gh_mod.GitError("no finished run found")
    if run.get("status") != "completed":
        raise gh_mod.GitError(f"run {run['id']} is still {run.get('status')}: try again in a minute")
    payload, good = gh_mod.deliver(gh, run)
    if payload is not None:
        apply_result(payload, args.verbose)
    return 0 if good and payload.get("ok") else 1


def cmd_runs(args) -> int:
    for r in gh_mod.client().runs(10):
        outcome = r.get("conclusion") or r.get("status")
        say(f"  {r['id']:<12} {outcome:<10} {(r.get('created_at') or '')[:19]}  {r.get('display_title', '')}")
    return 0


# ---------------------------------------------------------------- scan

def resolve_ipv4(host: str) -> list:
    """The IPv4 addresses of `host` as this machine's DNS gives them (Railway: the addresses of your *.up.railway.app domain)."""
    try:
        found = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        raise ConfigError(f"cannot resolve {host}: {e} (is DNS blocked here? write its address into a file and use --ips FILE)")
    return sorted({f[4][0] for f in found})


def cmd_scan(args) -> int:
    railway = env("CFP_TARGET") == "railway"
    if args.update_ranges and not railway:
        try:
            ok(f"{scan_mod.update_ranges()} Cloudflare IPv4 ranges saved in {scan_mod.ranges_path()}")
        except Exception as e:  # noqa: BLE001 (offline: the built-in list still works)
            warn(f"could not download the ranges ({e}): using the built-in list")
    st = settings("host", "auth_token")
    ports = parse_ports("443" if railway and args.ports == "all" else args.ports)
    if args.ips:
        try:
            with open(args.ips, encoding="utf-8") as f:
                source = scan_mod.parse_ip_text(f.read())
        except OSError as e:
            raise ConfigError(f"cannot read {args.ips}: {e.strerror}")
        if not source:
            raise ConfigError(f"{args.ips} holds no IP address or range")
    elif railway:
        source = resolve_ipv4(st.host)
        info(f"{st.host} resolves to {', '.join(source)}")
    else:
        source = scan_mod.load_ranges()
    ips = scan_mod.sample_ips(source, args.count)
    if not ips:
        raise ConfigError("no IP addresses to test")
    plans = scan_mod.port_plans(ports)
    info(f"testing {len(ips)} IPs x {len(ports)} ports against {bold(st.host)} "
         f"({'tunnel check on' if not args.no_tunnel else 'probe only'})")
    start = time.time()
    try:
        endpoints, meta = asyncio.run(scan_mod.scan(
            st, ips, plans, verify=args.verify, keep=args.keep, timeout=args.timeout, concurrency=args.concurrency,
            tunnel=not args.no_tunnel, progress=scan_mod.Progress()))
    except TunnelRefused as e:
        err(f"the Worker refused the test tunnel: {e}")
        return 1
    if not endpoints:
        err(scan_mod.explain_empty(meta) if not meta.get("answered") else
            f"{meta['answered']} edge(s) answered but no tunnel reached Telegram ({meta.get('tunnel_error', 'unknown reason')})")
        return 1
    if meta.get("warning"):
        warn(meta["warning"])
    path = save_endpoints(endpoints, meta)
    ok(f"{len(endpoints)} working endpoint(s) in {int(time.time() - start)}s, saved in {path}")
    for line in scan_mod.format_table(endpoints):
        say(line)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(scan_mod.endpoint_lines(endpoints))
        ok(f"ip:port list written to {args.out}")
    say("Next: ./cfproxy.sh serve   (or ./cfproxy.sh links to see the proxy links)")
    return 0


# ---------------------------------------------------------------- links

def link_host(args, listen: str) -> str:
    host = getattr(args, "host", None) or env("PUBLIC_HOST")
    if host:
        return host
    return lan_ip() if listen in ("0.0.0.0", "::") else "127.0.0.1"


def build_links(st: Settings, host: str, socks: bool, mtproto: bool, socks_port: int, mtproto_port: int) -> dict:
    out = {}
    if mtproto and st.mtproto_secret:
        out["MTProto"] = mtproto_links(host, mtproto_port, st.mtproto_secret)
    if socks:
        out["SOCKS5"] = socks_links(host, socks_port, st.socks_user, st.socks_pass)
    return out


def print_links(links: dict) -> None:
    for kind, items in links.items():
        say(bold(kind))
        for link in items:
            print(link, flush=True)


def cmd_links(args) -> int:
    st = Settings.from_env()
    st.require("mtproto_secret")
    st.socks_port = args.socks_port or st.socks_port
    st.mtproto_port = args.mtproto_port or st.mtproto_port
    links = build_links(st, link_host(args, args.listen), env("ALLOW", "all") != "telegram",
                        True, st.socks_port, st.mtproto_port)
    print_links(links)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(link for items in links.values() for link in items) + "\n")
        ok(f"links written to {args.out}")
    say(dim("These addresses are the local bridge (./cfproxy.sh serve). Telegram: tap a tg:// link, or "
            "Settings > Data and Storage > Proxy."))
    return 0


# ---------------------------------------------------------------- serve

def pools_for(endpoints: list, socks: bool, mtproto: bool, allow_plain_socks: bool):
    eps = [Endpoint.from_dict(e) for e in endpoints]
    tls = [e for e in eps if e.tls]
    socks_pool = None
    if socks:
        candidates = eps if allow_plain_socks else tls
        socks_pool = EndpointPool(candidates) if candidates else None
    return socks_pool, (EndpointPool(eps) if mtproto else None), eps


async def watch_endpoints(path: str, pools: list, allow_plain_socks: bool, stop: asyncio.Event) -> None:
    """A scan run in another terminal replaces the endpoints of the running bridge."""
    def stamp():
        try:
            return os.stat(path).st_mtime
        except OSError:
            return 0.0

    seen = stamp()
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), 15)
        except asyncio.TimeoutError:
            pass
        now = stamp()
        if now == seen:
            continue
        seen = now
        try:
            fresh, _ = load_endpoints(path)
        except ConfigError:
            continue
        eps = [Endpoint.from_dict(e) for e in fresh]
        for pool, tls_only in pools:
            wanted = [e for e in eps if e.tls] if tls_only and not allow_plain_socks else eps
            if wanted:
                pool.endpoints[:] = wanted
                pool._bad_until.clear()
        info(f"endpoints reloaded: {len(eps)} from the new scan")


async def serve_async(args, st: Settings, endpoints: list, path: str) -> None:
    want_socks = not args.no_socks and env("ALLOW", "all") != "telegram"
    want_mtproto = not args.no_mtproto
    socks_pool, mtproto_pool, eps = pools_for(endpoints, want_socks, want_mtproto, args.allow_plain_socks)
    if want_socks and socks_pool is None:
        warn("SOCKS5 is off: it would carry your traffic unencrypted over plain-HTTP ports. Scan with --ports tls, "
             "or start with --allow-plain-socks.")
    if env("ALLOW", "all") == "telegram" and not args.no_socks:
        info("ALLOW=telegram: this Worker is an MTProto-only exit, SOCKS5 is off")
    if want_mtproto and not st.mtproto_secret:
        raise ConfigError("MTPROTO_SECRET is not set: run './cfproxy.sh setup'")
    if want_mtproto and mt.BACKEND == "pure-python":
        warn("MTProto is running on the slow pure-Python AES (about 0.3 MB/s): fine for chat, slow for photos and "
             "video. Faster: Termux 'pkg install python-cryptography', elsewhere 'pip install cryptography' "
             "(or any system with OpenSSL's libcrypto, it is found automatically)")
    if socks_pool is not None and args.listen not in LOOPBACK and not st.socks_user:
        raise ConfigError("listening on a network address needs SOCKS_USER / SOCKS_PASS (run './cfproxy.sh setup')")
    if socks_pool is None and mtproto_pool is None:
        raise ConfigError("nothing to serve (MTProto and SOCKS5 are both off)")
    bridge = Bridge(st, socks_pool, mtproto_pool, listen=args.listen, verbose=args.verbose)
    try:
        await bridge.start()
    except OSError as e:
        raise ConfigError(f"cannot listen on {args.listen}: {e.strerror} (is another cfproxy running? use --socks-port / --mtproto-port)")
    host = link_host(args, args.listen)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):  # before the links appear: whoever reads them may stop it at once
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows: Ctrl+C arrives as KeyboardInterrupt
            pass
    info(f"cfproxy is running: {len(eps)} endpoint(s), best {eps[0]} ; Ctrl+C stops it")
    print_links(build_links(st, host, socks_pool is not None, mtproto_pool is not None,
                            bridge.socks_port, bridge.mtproto_port))
    watchers = [asyncio.ensure_future(watch_endpoints(
        path, [(p, t) for p, t in ((socks_pool, True), (mtproto_pool, False)) if p is not None],
        args.allow_plain_socks, stop))]
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 60 if args.verbose else 3600)
            except asyncio.TimeoutError:
                s = bridge.stats
                info(dim(f"active {s.active}, socks {s.socks}, mtproto {s.mtproto}, failed {s.failed}, "
                         f"up {s.up // 1024} KB, down {s.down // 1024} KB"))
    finally:
        for w in watchers:
            w.cancel()
        await bridge.close()
        info("stopped")


def cmd_serve(args) -> int:
    st = settings("host", "auth_token")
    st.socks_port = args.socks_port if args.socks_port is not None else st.socks_port
    st.mtproto_port = args.mtproto_port if args.mtproto_port is not None else st.mtproto_port
    endpoints, meta = load_pool_data(args)
    path = args.endpoints or endpoints_path()
    if meta.get("host") and meta["host"] != st.host:
        warn(f"the scan was made for {meta['host']} but WORKER_HOST is {st.host}: run './cfproxy.sh scan' again")
    try:
        asyncio.run(serve_async(args, st, endpoints, path))
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- test and status

async def exit_ip(endpoint: Endpoint, st: Settings, timeout: float) -> str:
    """The address the world sees for traffic that leaves through the Worker (asks a plain-HTTP service)."""
    tunnel = await Tunnel.open(endpoint, st, *EXIT_IP_TARGET, timeout)
    try:
        await tunnel.send(f"GET / HTTP/1.1\r\nHost: {EXIT_IP_TARGET[0]}\r\nConnection: close\r\n\r\n".encode())
        raw = b""
        while True:
            _, sep, body = raw.partition(b"\r\n\r\n")
            if sep and body.strip():
                break
            data = await asyncio.wait_for(tunnel.recv(), timeout)
            if data is None:
                break
            raw += data
    finally:
        await tunnel.close()
    body = raw.partition(b"\r\n\r\n")[2].decode("utf-8", "replace").strip()
    return body.splitlines()[0] if body else ""


async def run_tests(st: Settings, endpoints: list, count: int, timeout: float, want_exit_ip: bool) -> int:
    good = []
    say(f"  {'#':>2}  {'ENDPOINT':<22} {'PROBE':>8}  RESULT")
    for i, row in enumerate(endpoints[:count], 1):
        endpoint = Endpoint.from_dict(row)
        probe = await scan_mod.probe_pair(endpoint.ip, endpoint.port, endpoint.tls, st, timeout)
        if not probe["ok"]:
            say(f"  {i:>2}  {str(endpoint):<22} {'-':>8}  {err_text(probe['error'])}")
            continue
        try:
            tunnel = await scan_mod.tunnel_once(endpoint, st, max(timeout, 8.0))
        except TunnelRefused as e:
            say(f"  {i:>2}  {str(endpoint):<22} {probe['ms']:>5.0f} ms  refused by the Worker: {e}")
            continue
        if tunnel["ok"]:
            good.append(endpoint)
            say(f"  {i:>2}  {str(endpoint):<22} {probe['ms']:>5.0f} ms  Telegram answered in {tunnel['ms']:.0f} ms")
        else:
            say(f"  {i:>2}  {str(endpoint):<22} {probe['ms']:>5.0f} ms  tunnel failed: {tunnel['error']}")
    tested = min(count, len(endpoints))
    (ok if good else err)(f"{len(good)} of {tested} endpoint(s) carry a tunnel to Telegram")
    if good and want_exit_ip:
        if env("ALLOW", "all") == "telegram":
            warn("ALLOW=telegram: the exit-address check is not possible (only Telegram addresses are allowed)")
        else:
            try:
                say(f"  exit address of the Worker: {bold(await exit_ip(good[0], st, max(timeout, 8.0)) or '?')}")
            except (TunnelError, asyncio.TimeoutError, OSError) as e:
                warn(f"exit-address check failed: {e}")
    return 0 if good else 1


def err_text(code: str) -> str:
    return {"timeout": "no answer (timeout)", "not the Worker": "answers, but it is not your Worker",
            "HTTP 404": "answers, but 404 (wrong WS_PATH, or not deployed yet)"}.get(code, code)


def cmd_test(args) -> int:
    st = settings("host", "auth_token")
    endpoints, _ = load_pool_data(args)
    info(f"testing the best {min(args.count, len(endpoints))} of {len(endpoints)} saved endpoint(s) for {st.host}")
    try:
        return asyncio.run(run_tests(st, endpoints, args.count, args.timeout, args.exit_ip))
    except KeyboardInterrupt:
        return 130


def cmd_status(args) -> int:
    st = Settings.from_env()
    mask = lambda v: (v[:3] + "..." + v[-2:]) if len(v) > 8 else ("set" if v else "-")  # noqa: E731
    say(bold("cfproxy " + VERSION) + dim(f"   settings: {env_file()}"))
    rows = (("deploy target", env("CFP_TARGET", "worker") + f" '{env('WORKER_NAME', '-')}'"),
            ("exit allowed to", env("ALLOW", "all")), ("worker host", st.host or "- (run deploy)"),
            ("ws path", mask(st.ws_path)), ("auth token", mask(st.auth_token)),
            ("mtproto secret", "set" if st.mtproto_secret else "-"), ("aes backend", mt.BACKEND),
            ("socks login", "set" if st.socks_user else "none"),
            ("github", f"{env('GITHUB_REPO', '-')} (token {'set' if gh_mod.github_token() else '-'})"),
            (("railway token", "set" if env("RAILWAY_API_TOKEN") else "-") if env("CFP_TARGET") == "railway"
             else ("cloudflare token", "set" if env("CF_API_TOKEN") else "-")))
    for label, value in rows:
        say(f"  {label:<17} {value}")
    try:
        endpoints, meta = load_endpoints(getattr(args, "endpoints", None) or None)
        say(f"  {'last scan':<17} {len(endpoints)} endpoint(s), {meta.get('scanned_at', '?')}, best {endpoints[0]['ip']}:{endpoints[0]['port']}")
    except ConfigError:
        endpoints = []
        say(f"  {'last scan':<17} none yet (./cfproxy.sh scan)")
    if not (st.host and st.auth_token):
        return 0
    probe = asyncio.run(scan_mod.probe_pair(st.host, 443, True, st, 8.0))
    if probe["ok"]:
        ok(f"{st.host} answers directly ({probe['ms']:.0f} ms, edge {probe['colo'] or '?'})")
        return 0
    warn(f"{st.host} does not answer directly ({err_text(probe['error'])})")
    for row in endpoints[:3]:
        e = Endpoint.from_dict(row)
        via = asyncio.run(scan_mod.probe_pair(e.ip, e.port, e.tls, st, 8.0))
        if via["ok"]:
            ok(f"it answers through the clean endpoint {e} ({via['ms']:.0f} ms)")
            return 0
    err("it does not answer through the saved endpoints either: deploy it, or scan again")
    return 1


# ---------------------------------------------------------------- command line

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cfproxy", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"cfproxy {VERSION}")
    sub = p.add_subparsers(dest="cmd", metavar="command", required=True)

    s = sub.add_parser("setup", help="ask for the tokens, make the secrets, write the .env file")
    s.add_argument("--non-interactive", action="store_true", help="never ask: use flags and the existing .env")
    for flag, dest in (("--github-token", "github_token"), ("--repo", "repo"), ("--cf-token", "cf_token"),
                       ("--cf-account", "cf_account"), ("--target", "target"), ("--allow", "allow"),
                       ("--domain", "domain"), ("--railway-token", "railway_token"),
                       ("--railway-workspace", "railway_workspace"), ("--railway-region", "railway_region")):
        s.add_argument(flag, dest=dest, default=None)

    s = sub.add_parser("init", help="create the GitHub repository, push the deploy files, send the settings")
    s.add_argument("--public", action="store_true", help="create a public repository (default: private)")

    for name, text in (("deploy", "put the Worker / Pages project / Railway service online"), ("destroy", "delete it again")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--target", choices=gh_mod.TARGETS, default=None)
        s.add_argument("--timeout", type=int, default=1800, help="seconds to wait for the workflow")
        s.add_argument("-v", "--verbose", action="store_true", help="show wrangler's own output too")
        if name == "destroy":
            s.add_argument("--yes", action="store_true", help="do not ask for a confirmation")

    s = sub.add_parser("check", help="is everything ready for deploy?")
    s.add_argument("--remote", "--cloudflare", dest="cloudflare", action="store_true",
                   help="also check the Cloudflare / Railway token (runs the workflow)")
    s.add_argument("-v", "--verbose", action="store_true")

    s = sub.add_parser("fetch", help="bring back the result of an earlier workflow run")
    s.add_argument("run_id", nargs="?", default="")
    s.add_argument("-v", "--verbose", action="store_true")
    sub.add_parser("runs", help="the latest workflow runs")

    s = sub.add_parser("scan", help="test Cloudflare IPs x ports and keep the ones that work")
    s.add_argument("--ports", default="all", help="all | tls | plain | 443,8443,... (default: all 13 Cloudflare ports; Railway: 443)")
    s.add_argument("--count", type=int, default=scan_mod.DEFAULT_COUNT, help="random IPs to try")
    s.add_argument("--ips", metavar="FILE", help="test the IPs / ranges in this file instead of random ones")
    s.add_argument("--verify", type=int, default=scan_mod.DEFAULT_VERIFY, help="candidates that get the tunnel test")
    s.add_argument("--keep", type=int, default=scan_mod.DEFAULT_KEEP, help="endpoints to keep")
    s.add_argument("--timeout", type=float, default=5.0)
    s.add_argument("--concurrency", type=int, default=scan_mod.DEFAULT_CONCURRENCY)
    s.add_argument("--no-tunnel", action="store_true", help="only probe (faster, but proves less)")
    s.add_argument("--update-ranges", action="store_true", help="download Cloudflare's current IP ranges first")
    s.add_argument("--out", metavar="FILE", help="also write ip:port lines to this file")

    s = sub.add_parser("serve", help="run the local MTProto + SOCKS5 proxies")
    s.add_argument("--listen", default="127.0.0.1", help="address to listen on (0.0.0.0 = the whole network)")
    s.add_argument("--socks-port", type=int, default=None)
    s.add_argument("--mtproto-port", type=int, default=None)
    s.add_argument("--no-socks", action="store_true")
    s.add_argument("--no-mtproto", action="store_true")
    s.add_argument("--allow-plain-socks", action="store_true", help="let SOCKS5 use plain-HTTP ports (unencrypted!)")
    s.add_argument("--host", help="the address to put in the links (default: this machine)")
    s.add_argument("--endpoints", metavar="FILE", help="use another scan result")
    s.add_argument("-v", "--verbose", action="store_true")

    s = sub.add_parser("links", help="print the proxy links")
    s.add_argument("--listen", default="127.0.0.1")
    s.add_argument("--host", help="the address to put in the links")
    s.add_argument("--socks-port", type=int, default=None)
    s.add_argument("--mtproto-port", type=int, default=None)
    s.add_argument("--out", metavar="FILE", help="also write the links to this file")

    s = sub.add_parser("test", help="prove clean IP -> Cloudflare -> Worker -> Telegram again")
    s.add_argument("--count", type=int, default=10, help="how many of the saved endpoints to test")
    s.add_argument("--timeout", type=float, default=8.0)
    s.add_argument("--exit-ip", action="store_true", help="also show the address the Worker exits from")
    s.add_argument("--endpoints", metavar="FILE")

    s = sub.add_parser("status", help="settings, last scan, does the deployment answer?")
    s.add_argument("--endpoints", metavar="FILE")
    return p


COMMANDS = {"setup": cmd_setup, "init": cmd_init, "deploy": cmd_deploy, "destroy": cmd_destroy, "check": cmd_check,
            "fetch": cmd_fetch, "runs": cmd_runs, "scan": cmd_scan, "serve": cmd_serve, "links": cmd_links,
            "test": cmd_test, "status": cmd_status}


def main(argv=None) -> int:
    load_env()
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.cmd](args) or 0
    except KeyboardInterrupt:
        err("interrupted")
        return 130
    except ConfigError as e:
        err(str(e))
        return 2
    except gh_mod.GitError as e:
        err(str(e))
        hint = gh_mod.hint_for(e)
        if hint:
            warn(hint)
        return 1


if __name__ == "__main__":
    sys.exit(main())
