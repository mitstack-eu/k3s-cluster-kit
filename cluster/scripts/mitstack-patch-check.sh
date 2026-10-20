#!/bin/sh
# Writes how far the OS and k3s are behind their patches to patch-check.json,
# and exits 0 only on a pass.
# Usage: mitstack-patch-check, run hourly by its timer; the MITSTACK_* variables
# override its paths, tools and clock so it can run off a node.
# It exists so every node report carries a patch verdict the platform can read.
exec python3 - <<'PY'
import json, os, re, subprocess, sys, time, urllib.request
from datetime import datetime, timezone

E = lambda k, d: os.environ.get(k) or d
k3s = E("MITSTACK_K3S", "/usr/local/bin/k3s")
apt_get = E("MITSTACK_APT_GET", "apt-get")
uname = E("MITSTACK_UNAME", "uname")
os_release = E("MITSTACK_OS_RELEASE", "/etc/os-release")
boot = E("MITSTACK_BOOT_DIR", "/boot")
state = E("MITSTACK_STATE_DIR", "/var/lib/mitstack")
sentinel = E("MITSTACK_REBOOT_REQUIRED", "/var/run/reboot-required")
stamp = E("MITSTACK_APT_UPDATE_STAMP", "/var/lib/apt/periodic/update-success-stamp")
channels_url = E("MITSTACK_K3S_CHANNELS_URL", "https://update.k3s.io/v1-release/channels")
releases_url = E("MITSTACK_K3S_RELEASES_URL", "https://api.github.com/repos/k3s-io/k3s/releases?per_page=100")
FMT = "%Y-%m-%dT%H:%M:%SZ"
MAX = 14
VER = re.compile(r"v(\d+)\.(\d+)\.(\d+)(-[^+]*)?\+k3s(\d+)$")
now = E("MITSTACK_NOW", time.strftime(FMT, time.gmtime()))
utc = lambda s: datetime.strptime(s, FMT).replace(tzinfo=timezone.utc)
days = lambda s: max((utc(now) - utc(s)).days, 0)
text = lambda s, n: "".join(c for c in str(s) if " " <= c < "\x7f")[:n]
key = lambda m: tuple(int(m.group(i)) for i in (1, 2, 3, 5))


def run(*argv):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                       env=dict(os.environ, LC_ALL="C"))
    if p.returncode:
        raise RuntimeError("%s exited %d: %s" % (argv[0], p.returncode, p.stderr.decode("utf-8", "replace")[-99:]))
    return p.stdout.decode("utf-8", "replace")


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "mitstack"}), timeout=20) as r:
        return json.loads(r.read())


def ver(s):
    m = VER.match(s)
    if not m:
        raise ValueError("%.40r is no k3s version" % (s,))
    return m


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# running is the kubelet version the node reports, else k3s --version's.
def running():
    try:
        name = run(uname, "-n").strip()
        for n in json.loads(run(k3s, "kubectl", "get", "nodes", "-o", "json", "--request-timeout=10s"))["items"]:
            if n["metadata"]["name"] == name:
                return n["status"]["nodeInfo"]["kubeletVersion"]
    except Exception:
        pass
    return run(k3s, "--version").split()[2]


def k3s_part():
    p = dict.fromkeys(("running", "channel", "latest", "firstNewer", "firstNewerPublishedAt", "behindDays"))
    doing = "reading the running k3s"
    try:
        r = ver(running())
        p.update(running=r.group(0), channel="v%s.%s" % r.group(1, 2))
        doing = "reading the channels"
        latest = [c["latest"] for c in fetch(channels_url)["data"] if c["name"] == p["channel"]]
        doing = "reading the releases"
        releases = fetch(releases_url)
        if not isinstance(releases, list) or not latest:
            raise ValueError("no list of releases or no channel " + p["channel"])
        last = ver(latest[0])
        p.update(latest=last.group(0), behindDays=0)
        if key(r) < key(last):
            newer = []
            for x in releases:
                m = VER.match(x.get("tag_name") or "")
                if m and not (m.group(4) or x.get("prerelease") or x.get("draft")) and m.group(1, 2) == r.group(1, 2) and key(m) > key(r):
                    newer.append((key(m), m.group(0), x["published_at"]))
            if not newer:
                raise ValueError("no release newer than " + p["running"])
            _, tag, published = min(newer)
            p.update(behindDays=days(published), firstNewer=tag, firstNewerPublishedAt=published)
        p["verdict"] = "fail" if p["behindDays"] > MAX else "pass"
    except Exception as e:
        p.update(behindDays=None, verdict="unknown", error=text("%s: %s" % (doing, e), 160))
    return p


def os_part():
    release = dict(l.partition("=")[::2] for l in read(os_release).splitlines())
    try:
        kernel = run(uname, "-r").strip()
    except Exception:
        kernel = "unknown"
    try:
        kernels = [n[8:] for n in os.listdir(boot) if n.startswith("vmlinuz-")]
    except OSError:
        kernels = []
    vkey = lambda s: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)]
    p = {"running": text("%s, kernel %s" % (release.get("PRETTY_NAME", "").strip("\"'"), kernel), 120),
         "latestKernel": text(max(kernels, key=vkey), 99) if kernels else None,
         "pendingUpgrades": [], "rebootRequired": os.path.exists(sentinel)}
    try:
        p["listsRefreshedAt"] = time.strftime(FMT, time.gmtime(os.stat(stamp).st_mtime))
    except OSError:
        p.update(listsRefreshedAt=None, error="no apt update stamp, so the lists are of unknown age")
    try:
        room = 2046
        for m in re.finditer(r"^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+)", run(apt_get, "-s", "dist-upgrade"), re.M):
            e = dict(zip(("package", "installed", "candidate"), m.groups()))
            room -= len(json.dumps(e, separators=(",", ":"))) + 1
            if room < 0:
                break
            p["pendingUpgrades"].append(e)
    except Exception as e:
        p.update(pendingUpgrades=None, error=text("reading the pending upgrades: %s" % e, 160))
    path = state + "/os-behind-since"
    since = read(path).strip() or None
    try:
        since and utc(since)
    except ValueError:
        since = None
    if p["rebootRequired"] or p["pendingUpgrades"]:
        since = since or now
    elif p["pendingUpgrades"] is not None:
        since = None
    if since:
        with open(path, "w") as f:
            f.write(since)
    elif os.path.exists(path):
        os.remove(path)
    p.update(behindSince=since, behindDays=days(since) if since else 0)
    stale = p["listsRefreshedAt"] and days(p["listsRefreshedAt"]) > MAX
    p["verdict"] = "fail" if p["behindDays"] > MAX or stale else "unknown" if "error" in p else "pass"
    return p


os.umask(0o077)
os.makedirs(state, exist_ok=True)
k, o = k3s_part(), os_part()
both = (o["verdict"], k["verdict"])
verdict = "fail" if "fail" in both else "unknown" if "unknown" in both else "pass"
result = {"checkedAt": now, "verdict": verdict, "maxBehindDays": MAX, "os": o, "k3s": k}
out = json.dumps(result, separators=(",", ":"))
while len(out) > 4095 and o["pendingUpgrades"]:
    o["pendingUpgrades"].pop()
    out = json.dumps(result, separators=(",", ":"))
with open(state + "/patch-check.json.partial", "w") as f:
    f.write(out + "\n")
os.replace(state + "/patch-check.json.partial", state + "/patch-check.json")
print("mitstack-patch-check: %s (os %s, k3s %s)" % (verdict, both[0], both[1]), *[p["error"] for p in (o, k) if "error" in p], sep="; ")
sys.exit(verdict != "pass")
PY
