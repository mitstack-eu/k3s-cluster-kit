#!/usr/bin/env python3
# Runs kube-bench's k3s CIS benchmark and kubescape's NSA framework on the
# node, each at most once a day, and keeps a bounded summary of each run in
# kube-bench.json and kubescape.json for the node report to carry.
# Usage: python3 -I mitstack-scan.py, started detached as the transient unit
# mitstack-scan.service by mitstack-report once it has checked these bytes
# against the SHA-256 the user data pins; the MITSTACK_* variables override
# its paths, tools and downloads so it can run off a node.
# It exists so the platform can judge the cluster against the CIS Kubernetes
# Benchmark and the NSA and CISA guide, and it ships through the cluster
# repository because the user data has no room for it.
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

E = lambda k, d: os.environ.get(k) or d
state = E("MITSTACK_STATE_DIR", "/var/lib/mitstack")
k3s = E("MITSTACK_K3S", "/usr/local/bin/k3s")
kubeconfig = E("MITSTACK_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
github = E("MITSTACK_SCAN_URL", "https://github.com/")
raw = E("MITSTACK_SCAN_RAW_URL", "https://raw.githubusercontent.com/")
tools = state + "/scan-tools"
FMT = "%Y-%m-%dT%H:%M:%SZ"

# Each download set is its base, its files and their SHA-256 joined in
# order, as cat a b | sha256sum prints it. kube-bench's releases stop at
# k3s-cis-1.9, so its config comes from the commit that added k3s-cis-1.11.
KUBE_BENCH = (github + "aquasecurity/kube-bench/releases/download/v0.16.0/",
              ["kube-bench_0.16.0_linux_amd64.tar.gz"],
              "sha256:82dbc7e598740dc9344d41f8ad0b8210d57c4c00bdb2c5f1d8a69a2b98baddcf")
KUBE_BENCH_CONFIG = (raw + "aquasecurity/kube-bench/e278a5915a982f2756026de6e2f9ca77077ef9f9/cfg/",
                     ["config.yaml"] + ["k3s-cis-1.11/%s.yaml" % n
                                        for n in ("config", "master", "etcd", "controlplane", "node", "policies")],
                     "sha256:543e30202ac23ef52b7087d1add8cdf852a320342f73718f62f4e8f1be9790f6")
KUBESCAPE = (github + "kubescape/kubescape/releases/download/v4.0.15/",
             ["kubescape_4.0.15_linux_amd64"],
             "sha256:011569dbcde85afc96cf63262e4f967166b6680fd70a623e9065334b6767b244")
NSA_FRAMEWORK = (github + "kubescape/regolibrary/releases/download/v2.0.38/",
                 ["nsa", "default_config_inputs"],
                 "sha256:b40328283b5cffe90884ae1da5d9b652ab8c4be384d7367e895fa8873e804291")
PROFILE = "k3s-cis-1.11"
TARGETS = "master,etcd,controlplane,node,policies"
SEVERITIES = ("Critical", "High", "Medium", "Low")
SCAN_EVERY, RETRY_AFTER = 86400, 3600
FAILED_LIMIT, RESOURCES_LIMIT, ERROR_LIMIT = 12000, 4000, 1000


def clip(s, n, from_end=False):
    s = str(s).replace("\0", "")
    return s[-n:] if from_end else s[:n]


# bounded keeps whole entries from the first while their JSON text fits in
# budget bytes.
def bounded(entries, budget):
    kept = []
    for e in entries:
        budget -= len(json.dumps(e)) + 2
        if budget < 0:
            break
        kept.append(e)
    return kept


def write_private(path, data, mode=0o600):
    fd = os.open(path + ".partial", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(path + ".partial", path)


def digest(paths):
    h = hashlib.sha256()
    for p in paths:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


# fetch downloads a set once into a directory named by its digest and checks
# the digest on every run, so a set changed on disk is removed and the run
# fails; kube-bench's binary is extracted afresh from its checked archive on
# every run for the same reason.
def fetch(base, names, want):
    d = tools + "/" + want.removeprefix("sha256:")
    if not os.path.isdir(d):
        shutil.rmtree(d + ".partial", True)
        for n in names:
            os.makedirs(os.path.dirname(d + ".partial/" + n), exist_ok=True)
            with urllib.request.urlopen(base + n, timeout=60) as r, open(d + ".partial/" + n, "wb") as f:
                shutil.copyfileobj(r, f, 1 << 20)
        os.replace(d + ".partial", d)
    got = "sha256:" + digest(d + "/" + n for n in names)
    if got != want:
        shutil.rmtree(d)
        raise ValueError("%s%s has %s, want %s" % (base, names[0], got, want))
    return d + "/"


def run(argv, timeout):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                       env=dict(os.environ, HOME=tools, KUBECONFIG=kubeconfig))
    if p.returncode:
        raise RuntimeError("%s exited %d: %s" % (os.path.basename(argv[0]), p.returncode,
                                                  clip(p.stderr.decode("utf-8", "replace"), 600, True)))
    return p.stdout


# kube_bench names its k3s profile, since kube-bench never picks one for k3s;
# k3s-cis-1.11 is the newest, covering Kubernetes 1.29 and later, and the only
# one pinned.
def kube_bench(s, version, work):
    m = re.match(r"v1\.(\d+)\.", version)
    if not m or int(m.group(1)) < 29:
        raise ValueError("no pinned k3s-cis profile covers Kubernetes %s" % version)
    s.update(profile=PROFILE, kubernetesVersion=version)
    exe = os.environ.get("MITSTACK_KUBE_BENCH")
    config = os.path.dirname(exe or "") + "/"
    if not exe:
        archive = fetch(*KUBE_BENCH) + KUBE_BENCH[1][0]
        exe = work + "/kube-bench"
        with tarfile.open(archive) as tar:
            write_private(exe, tar.extractfile("kube-bench").read(), 0o700)
        config = fetch(*KUBE_BENCH_CONFIG)
    out = json.loads(run([exe, "run", "--config-dir", config, "--benchmark", PROFILE, "--targets", TARGETS, "--json"], 900))
    totals = out["Totals"]
    s["totals"] = {k: totals["total_" + k] for k in ("pass", "fail", "warn", "info")}
    s["failed"] = bounded(({"id": r["test_number"], "scored": r["scored"] is True, "text": clip(r["test_desc"], 160)}
                           for c in out["Controls"] for g in c["tests"] for r in g["results"] if r["status"] == "FAIL"),
                          FAILED_LIMIT)


def workload(o):
    meta = o.get("metadata") or o
    return {"namespace": meta.get("namespace"), "kind": o.get("kind"), "name": meta.get("name")}


def severity_rank(control):
    return (SEVERITIES + (control.get("severity"),)).index(control.get("severity"))


# kubescape lists every failed control, the most severe first, with the
# resources each Critical or High control failed on. It reads an empty
# exception list, since only the platform's exempt list may exempt a finding,
# and scans no host, since that would deploy a sensor into the cluster.
def kubescape(s, version, work):
    exe = os.environ.get("MITSTACK_KUBESCAPE")
    framework = os.path.dirname(exe or "") + "/"
    if not exe:
        exe = fetch(*KUBESCAPE) + KUBESCAPE[1][0]
        os.chmod(exe, 0o700)
        framework = fetch(*NSA_FRAMEWORK)
    with open(framework + "default_config_inputs", "rb") as f:
        inputs = json.load(f)["settings"]["postureControlInputs"]
    write_private(work + "/inputs.json", json.dumps(inputs).encode())
    write_private(work + "/exceptions.json", b"[]")
    run([exe, "scan", "framework", "nsa", "--kubeconfig", kubeconfig, "--use-from", framework + "nsa",
         "--controls-config", work + "/inputs.json", "--exceptions", work + "/exceptions.json", "--host-scan=false",
         "--format", "json", "--output", work + "/kubescape.json", "--cache-dir", tools + "/kubescape-cache"], 1800)
    with open(work + "/kubescape.json", "rb") as f:
        out = json.load(f)
    summary = out["summaryDetails"]
    objects = {r["resourceID"]: r.get("object") or {} for r in out.get("resources") or []}
    failing = {}
    for r in out.get("results") or []:
        for c in r["controls"]:
            if c["status"]["status"] == "failed":
                failing.setdefault(c["controlID"], []).append(workload(objects.get(r["resourceID"]) or {}))
    controls = sorted(((i, c) for i, c in summary["controls"].items() if c["status"] == "failed"),
                      key=lambda ic: (severity_rank(ic[1]), ic[0]))
    s.update(version=out["metadata"]["scanMetadata"]["kubescapeVersion"], framework="NSA", controlsVersion="v2.0.38",
             complianceScore=summary.get("complianceScore"), failedControlsBySeverity=summary["controlsSeverityCounters"])
    s["failed"] = bounded(({"id": i, "name": c["name"], "severity": c.get("severity"),
                            "failedResources": c["ResourceCounters"]["failedResources"],
                            "resources": bounded(sorted(failing.get(i, []), key=json.dumps), RESOURCES_LIMIT)
                            if c.get("severity") in SEVERITIES[:2] else []}
                           for i, c in controls), FAILED_LIMIT)


# due is whether a scan's kept summary is missing, a day old, an hour old and
# an error, or dated in the future, as a clock stepped back leaves it.
def due(path):
    try:
        age = time.time() - os.stat(path).st_mtime
        with open(path, "rb") as f:
            last = json.load(f)
    except (OSError, ValueError):
        return True
    return age < 0 or age >= (RETRY_AFTER if not isinstance(last, dict) or "error" in last else SCAN_EVERY)


def scan(name, version, measure, kubernetes):
    path = state + "/" + name + ".json"
    if not due(path):
        return "%s: not due" % name
    s = {"tool": name, "version": version, "startedAt": time.strftime(FMT, time.gmtime())}
    try:
        with tempfile.TemporaryDirectory() as work:
            measure(s, kubernetes, work)
    except Exception as e:
        s["error"] = clip("%s: %s" % (type(e).__name__, e), ERROR_LIMIT)
    s["finishedAt"] = time.strftime(FMT, time.gmtime())
    write_private(path, json.dumps(s, separators=(",", ":")).encode())
    return "%s: %s" % (name, "failed: " + s["error"] if "error" in s else "ran")


# finish keeps the run's one-line outcome in scan-run.json for the next node
# report, since the run is detached from the report that started it.
def finish(line, status):
    write_private(state + "/scan-run.json", json.dumps({"finishedAt": time.strftime(FMT, time.gmtime()), "exitStatus": status,
                                                        "output": clip(line, 600)}).encode())
    print(line)
    sys.exit(status)


# The node's kubelet version is the Kubernetes the profile must match, and
# reading it shows the cluster answers, since a scan of no cluster proves
# nothing.
os.umask(0o077)
os.makedirs(tools, exist_ok=True)
try:
    kubernetes = run([k3s, "kubectl", "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kubeletVersion}",
                      "--request-timeout=10s"], 60).decode().strip()
except Exception as e:
    finish("mitstack-scan: the cluster does not answer, so no scan ran: %s" % clip(e, 400), 1)
finish("mitstack-scan: %s; %s" % (scan("kube-bench", "v0.16.0", kube_bench, kubernetes),
                                  scan("kubescape", "v4.0.15", kubescape, kubernetes)), 0)
