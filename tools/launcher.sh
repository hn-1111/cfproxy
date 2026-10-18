#!/usr/bin/env bash
# cfproxy: one file, nothing else to download. Copy THIS file to any machine and run it.
#
#   ./cfproxy.sh setup | init | deploy | scan | serve | links | test | status | destroy | ...
#   ./cfproxy.sh --help
#
# The whole client (lib/*.py) and the files that `init` sends to your GitHub repository (the workflow, the Worker,
# the deploy script) are packed INSIDE this file. The first run unpacks them into ~/.cfproxy/app/ (CFPROXY_HOME
# changes the folder); `init`, `deploy`, `destroy`, `check` then control your GitHub repository through the GitHub
# API from this machine. Needs only Python 3.9+ (standard library: nothing to install).
#
# This file is generated: edit lib/, worker/ or tools/launcher.sh, then run `python3 tools/build.py`.
# (When a project folder sits next to this file, i.e. lib/cfproxy.py, that folder is used instead of the packed copy.)
set -eu

# the folder of this script, also when it is started through a symlink
src="$0"
while [ -L "$src" ]; do
  dir="$(cd -P "$(dirname "$src")" && pwd)"
  src="$(readlink "$src")"
  case "$src" in /*) ;; *) src="$dir/$src" ;; esac
done
here="$(cd -P "$(dirname "$src")" && pwd)"

python=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 \
     && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    python="$candidate"
    break
  fi
done

if [ -z "$python" ]; then
  echo "[ERROR] Python 3.9 or newer is needed and was not found." >&2
  echo "        Termux: pkg install python   |   Debian/Ubuntu: sudo apt install python3   |   macOS: brew install python" >&2
  exit 127
fi

if [ "$#" -eq 0 ]; then
  set -- --help
fi

# a full project folder next to this file (a git checkout): run that one, so edits take effect at once
if [ -f "$here/lib/cfproxy.py" ]; then
  exec "$python" "$here/lib/cfproxy.py" "$@"
fi

# Unpacks the project that is packed at the end of this file (once per version) and prints the folder it is in.
unpack() {
  "$python" - "$1" <<'PYEOF'
import base64, hashlib, io, os, re, shutil, sys, tempfile, zipfile

MARK = b"#__CFPROXY" + b"_PAYLOAD__"  # written in two pieces so that this line is not mistaken for the marker


def fail(text):
    sys.stderr.write("[ERROR] " + text + "\n")
    sys.exit(1)


try:
    with open(sys.argv[1], "rb") as f:
        blob = f.read()
except OSError as e:
    fail("cannot read %s (%s): save cfproxy.sh as a file and run it from there "
         "(for example: curl -fsSL <url> -o cfproxy.sh && bash cfproxy.sh setup)" % (sys.argv[1], e.strerror))
start = blob.find(MARK)
if start < 0:
    fail("the project is not packed in %s (the file was cut short or edited): copy cfproxy.sh again" % sys.argv[1])
try:
    raw = base64.b64decode(blob[start + len(MARK):])  # '#', spaces and line ends are not base64: they are skipped
    archive = zipfile.ZipFile(io.BytesIO(raw))
except (ValueError, zipfile.BadZipFile):
    fail("the project packed in %s is damaged: copy cfproxy.sh again" % sys.argv[1])

ident = hashlib.sha256(raw).hexdigest()[:12]
home = os.environ.get("CFPROXY_HOME") or os.path.join(os.path.expanduser("~"), ".cfproxy")
base = os.path.join(home, "app")
dest = os.path.join(base, ident)
done = os.path.join(dest, ".complete")

if not os.path.isfile(done):
    try:
        os.makedirs(base, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix=".unpack-", dir=base)
    except OSError as e:
        fail("cannot create %s (%s): set CFPROXY_HOME to a folder you can write to" % (base, e.strerror))
    try:
        for member in archive.infolist():
            parts = member.filename.split("/")
            if member.filename.endswith("/"):
                continue
            if member.filename.startswith("/") or "\\" in member.filename or ".." in parts or ":" in parts[0]:
                fail("unsafe path in the packed project: " + member.filename)
            target = os.path.join(tmp, *parts)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as out:
                out.write(archive.read(member))
        open(os.path.join(tmp, ".complete"), "w").close()
        if os.path.isdir(dest) and not os.path.isfile(done):
            shutil.rmtree(dest, ignore_errors=True)  # left half-done by something else
        try:
            os.rename(tmp, dest)
        except OSError:
            if not os.path.isfile(done):  # not a second cfproxy that was faster: a real failure
                raise
    except OSError as e:
        fail("cannot unpack into %s (%s): set CFPROXY_HOME to a folder you can write to" % (base, e.strerror))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name in os.listdir(base):  # older versions are not needed any more
        if name != ident and re.fullmatch(r"[0-9a-f]{12}", name):
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)

print(dest)
PYEOF
}

app="$(unpack "$src")" || exit 1
exec "$python" "$app/lib/cfproxy.py" "$@"
exit 1

# ---- everything below is data and never runs: the project (lib/, worker/, the workflow) as a base64 zip ----
