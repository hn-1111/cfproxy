#!/usr/bin/env python3
"""Builds the single-file client: cfproxy.sh = tools/launcher.sh + the project packed at its end.

  python3 tools/build.py            write cfproxy.sh (run it after every change in lib/, worker/ or tools/launcher.sh)
  python3 tools/build.py --check    exit 1 when cfproxy.sh does not match the sources (CI runs this)
  python3 tools/build.py --out F    write the file to F instead

The packed part is a zip (base64, every line a shell comment) with exactly what a client machine needs:
lib/*.py for the command line, and the files `init` sends to the GitHub repository (.github/workflows/deploy.yml,
worker/index.js, server/index.mjs, lib/cfp_deploy.py, lib/cfp_crypto.py). The build is deterministic: the same sources give the same file.
Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import glob
import io
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = "cfproxy.sh"
LAUNCHER = os.path.join("tools", "launcher.sh")
EXTRA_FILES = ("worker/index.js", "server/index.mjs", ".github/workflows/deploy.yml")
MARK = b"#__CFPROXY" + b"_PAYLOAD__"  # the line after which the packed project starts (launcher.sh holds the same split)
LINE = 76


def payload_names(root: str = ROOT) -> list:
    """The files that travel inside cfproxy.sh (relative paths with '/'), sorted."""
    names = sorted("lib/" + os.path.basename(p) for p in glob.glob(os.path.join(root, "lib", "*.py")))
    return names + list(EXTRA_FILES)


def read_source(root: str, rel: str) -> bytes:
    with open(os.path.join(root, *rel.split("/")), "rb") as f:
        return f.read()


def make_zip(files: dict) -> bytes:
    """A zip that does not depend on the clock, the machine or the file order."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[name], compresslevel=9)
    return buf.getvalue()


def assemble(launcher: bytes, zipped: bytes) -> bytes:
    """The launcher, the marker line and the zip as base64 (every line a shell comment)."""
    packed = base64.b64encode(zipped)
    lines = [b"#" + packed[i:i + LINE] + b"\n" for i in range(0, len(packed), LINE)]
    return launcher + MARK + b"\n" + b"".join(lines)


def build(root: str = ROOT) -> bytes:
    for rel in (LAUNCHER, *payload_names(root)):
        if not os.path.isfile(os.path.join(root, *rel.split("/"))):
            raise SystemExit(f"[ERROR] {rel} is missing: run this from a complete project folder")
    launcher = read_source(root, LAUNCHER)
    if not launcher.endswith(b"\n") or MARK in launcher:
        raise SystemExit(f"[ERROR] {LAUNCHER} must end with a line break and must not contain the payload marker")
    return assemble(launcher, make_zip({n: read_source(root, n) for n in payload_names(root)}))


def read_zip(blob: bytes) -> tuple:
    """(the launcher part, the packed zip) of a built cfproxy.sh."""
    start = blob.find(MARK)
    if start < 0:
        raise ValueError("no packed project in the file")
    return blob[:start], base64.b64decode(blob[start + len(MARK):])  # '#' and line ends are not base64: skipped


def read_payload(blob: bytes) -> tuple:
    """(the launcher part, {name: bytes} of the packed project) of a built cfproxy.sh."""
    launcher, raw = read_zip(blob)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return launcher, {i.filename: archive.read(i) for i in archive.infolist() if not i.filename.endswith("/")}


def problems(root: str = ROOT, path: str | None = None) -> list:
    """Why the built file is not current (an empty list: it is)."""
    path = path or os.path.join(root, OUTPUT)
    try:
        with open(path, "rb") as f:
            blob = f.read()
        launcher, packed = read_payload(blob)
    except OSError as e:
        return [f"{path}: {e.strerror}"]
    except (ValueError, zipfile.BadZipFile) as e:
        return [f"{path}: {e}"]
    found = []
    if launcher != read_source(root, LAUNCHER):
        found.append(f"the launcher part differs from {LAUNCHER}")
    wanted = payload_names(root)
    found += [f"{n}: not packed" for n in wanted if n not in packed]
    found += [f"{n}: packed but not a project file" for n in sorted(packed) if n not in wanted]
    found += [f"{n}: differs from the source" for n in wanted if n in packed and packed[n] != read_source(root, n)]
    return found


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true", help="only check that cfproxy.sh is current")
    p.add_argument("--out", metavar="FILE", help=f"write the result here (default: {OUTPUT} in the project folder)")
    args = p.parse_args(argv)
    if args.check:
        found = problems()
        for line in found:
            sys.stderr.write(f"[ERROR] {OUTPUT}: {line}\n")
        if found:
            sys.stderr.write(f"[ERROR] {OUTPUT} is out of date: run  python3 tools/build.py\n")
            return 1
        print(f"{OUTPUT} is current ({len(payload_names())} files packed)")
        return 0
    data = build()
    target = args.out or os.path.join(ROOT, OUTPUT)
    temp = target + ".tmp"
    with open(temp, "wb") as f:
        f.write(data)
    os.chmod(temp, 0o755)
    os.replace(temp, target)
    print(f"wrote {target}: {len(data) // 1024} KB, {len(payload_names())} files packed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
