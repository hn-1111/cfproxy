"""Shared helpers: logging, the .env file, settings, ports, proxy links and the endpoint store.

Standard library only. Everything is configured through environment variables; locally they come from
~/.cfproxy/.env (override the folder with CFPROXY_HOME), on the GitHub runner from the repository secrets.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass

VERSION = "1.0.0"
APP = "cfproxy"
USER_AGENT = f"{APP}/{VERSION}"

# The ports Cloudflare proxies for a hostname: six HTTPS ports and seven plain HTTP ports.
TLS_PORTS = (443, 8443, 2053, 2083, 2087, 2096)
PLAIN_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)
ALL_PORTS = TLS_PORTS + PLAIN_PORTS

# https://www.cloudflare.com/ips-v4 (built in so the scanner works offline; `scan --update-ranges` fetches the list)
CF_RANGES_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)

# Telegram data centres (the list Telegram Desktop ships with). The Worker connects to these for MTProto.
TG_PORT = 443
TG_DCS = {
    1: ["149.154.175.50"],
    2: ["149.154.167.51", "95.161.76.100"],
    3: ["149.154.175.100"],
    4: ["149.154.167.91"],
    5: ["149.154.171.5"],
}
DEFAULT_TARGET = ("149.154.167.51", TG_PORT)  # what the scanner and `test` open a tunnel to

IS_TTY = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------- logging (stderr: stdout is for data)

def _col(code: str) -> str:
    return f"\033[{code}m" if IS_TTY else ""


def _emit(tag: str, color: str, msg: str) -> None:
    sys.stderr.write(f"{_col(color)}{tag}{_col('0')} {msg}\n")
    sys.stderr.flush()


def info(msg: str) -> None:
    _emit("==>", "36", msg)


def ok(msg: str) -> None:
    _emit("[OK]", "32", msg)


def warn(msg: str) -> None:
    _emit("[WARN]", "33", msg)


def err(msg: str) -> None:
    _emit("[ERROR]", "31", msg)


def say(text: str = "") -> None:
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def bold(text: str) -> str:
    return f"{_col('1')}{text}{_col('0')}"


def dim(text: str) -> str:
    return f"{_col('2')}{text}{_col('0')}"


# ---------------------------------------------------------------- .env

def home() -> str:
    return os.environ.get("CFPROXY_HOME") or os.path.join(os.path.expanduser("~"), ".cfproxy")


def env_file() -> str:
    return os.environ.get("CFPROXY_ENV_FILE") or os.path.join(home(), ".env")


def env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return v.strip() if v is not None and v.strip() != "" else default


def parse_env_text(text: str) -> dict:
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name] = value
    return values


def load_env(path: str | None = None) -> dict:
    """Reads the .env file into os.environ (variables that are already set win). Returns what the file held."""
    path = path or env_file()
    try:
        with open(path, encoding="utf-8") as f:
            values = parse_env_text(f.read())
    except OSError:
        return {}
    for name, value in values.items():
        if os.environ.get(name, "") == "":
            os.environ[name] = value
    return values


def env_set(path: str, name: str, value: str) -> None:
    """NAME="value" in the .env file: the first assignment is replaced (duplicates dropped), otherwise appended."""
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    pattern = re.compile(rf"^\s*(export\s+)?{re.escape(name)}=")
    out, done = [], False
    for line in lines:
        if pattern.match(line):
            if not done:
                out.append(f'{name}="{value}"')
                done = True
            continue
        out.append(line)
    if not done:
        out.append(f'{name}="{value}"')
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, path)
    os.environ[name] = value


# ---------------------------------------------------------------- ports

def parse_ports(raw: str, default=ALL_PORTS) -> list:
    """'443,8443' | 'tls' | 'plain' | 'all' (keywords can be mixed with numbers)."""
    if not raw or not raw.strip():
        return list(default)
    ports = []
    for part in re.split(r"[,\s]+", raw.strip().lower()):
        if not part:
            continue
        if part == "tls":
            found = list(TLS_PORTS)
        elif part == "plain":
            found = list(PLAIN_PORTS)
        elif part == "all":
            found = list(ALL_PORTS)
        elif part.isdigit() and 1 <= int(part) <= 65535:
            found = [int(part)]
        else:
            raise ConfigError(f"'{part}' is not a port (use numbers, or tls / plain / all)")
        for p in found:
            if p not in ports:
                ports.append(p)
    return ports


# ---------------------------------------------------------------- settings

@dataclass
class Settings:
    host: str = ""             # the Worker's hostname: SNI and Host header
    ws_path: str = "/ws"
    auth_token: str = ""
    mtproto_secret: str = ""   # 32 hex characters
    socks_user: str = ""
    socks_pass: str = ""
    socks_port: int = 1080
    mtproto_port: int = 1443
    ssl_context: object = None  # tests only: a context that trusts the test certificate

    @classmethod
    def from_env(cls) -> "Settings":
        def number(name, default):
            raw = env(name)
            if not raw:
                return default
            if not raw.isdigit() or not 1 <= int(raw) <= 65535:
                raise ConfigError(f"{name} must be a port number")
            return int(raw)

        path = env("WS_PATH", "/ws")
        return cls(
            host=env("WORKER_HOST") or env("CUSTOM_DOMAIN"),
            ws_path=path if path.startswith("/") else "/" + path,
            auth_token=env("AUTH_TOKEN"),
            mtproto_secret=env("MTPROTO_SECRET").lower(),
            socks_user=env("SOCKS_USER"),
            socks_pass=env("SOCKS_PASS"),
            socks_port=number("SOCKS_PORT", 1080),
            mtproto_port=number("MTPROTO_PORT", 1443),
        )

    def require(self, *names: str) -> None:
        messages = {
            "host": "WORKER_HOST is not set: run './cfproxy.sh deploy' (it finds the host) or put your domain in .env",
            "auth_token": "AUTH_TOKEN is not set: run './cfproxy.sh init'",
            "mtproto_secret": "MTPROTO_SECRET is not set (32 hex characters): run './cfproxy.sh init'",
        }
        for name in names:
            if not getattr(self, name):
                raise ConfigError(messages[name])
        if "mtproto_secret" in names and not re.fullmatch(r"[0-9a-f]{32}", self.mtproto_secret):
            raise ConfigError("MTPROTO_SECRET must be exactly 32 hex characters")


# ---------------------------------------------------------------- proxy links

def socks_links(host: str, port: int, user: str = "", password: str = "") -> list:
    q = {"server": host, "port": str(port)}
    if user:
        q.update({"user": user, "pass": password})
    query = urllib.parse.urlencode(q)
    auth = f"{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(password, safe='')}@" if user else ""
    return [f"tg://socks?{query}", f"https://t.me/socks?{query}", f"socks5://{auth}{host}:{port}"]


def mtproto_links(host: str, port: int, secret_hex: str) -> list:
    query = urllib.parse.urlencode({"server": host, "port": str(port), "secret": "dd" + secret_hex})
    return [f"tg://proxy?{query}", f"https://t.me/proxy?{query}"]


# ---------------------------------------------------------------- endpoint store (scan results)

def endpoints_path() -> str:
    return os.path.join(home(), "endpoints.json")


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def save_endpoints(endpoints: list, meta: dict, path: str | None = None) -> str:
    path = path or endpoints_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = {"version": 1, "scanned_at": now_iso(), **meta, "endpoints": endpoints}
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    return path


def load_endpoints(path: str | None = None) -> tuple:
    """(endpoints, meta). Raises ConfigError when there is no usable scan result."""
    path = path or endpoints_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise ConfigError("no scan result yet: run './cfproxy.sh scan' first")
    items = [e for e in data.get("endpoints", []) if e.get("ip") and e.get("port")]
    if not items:
        raise ConfigError("the last scan found no working endpoint: run './cfproxy.sh scan' again")
    meta = {k: v for k, v in data.items() if k != "endpoints"}
    return items, meta
