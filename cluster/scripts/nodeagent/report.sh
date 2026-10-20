#!/bin/sh
# Reports the node's journal, the cluster's, the hardening and the patching
# evidence to the mitstack platform, one attempt per run: the cluster reads
# this pod's service account allows, the Argo CD probes, and the host evidence
# mitstack-host left in host.tar.
# Usage: mitstack-report, run every five minutes by the report container of
# mitstack-node-agent.
# It exists because the node accepts no SSH, so what it reports is all the
# platform can see of it.
set -eu

report_url=${MITSTACK_REPORT_URL:-https://api.mitstack.dev/v1/cluster-reports}
token_file=${MITSTACK_TOKEN_FILE:-/var/run/mitstack/token}
host_dir=${MITSTACK_HOST_DIR:-/run/mitstack-host}
probe_ns=mitstack-metadata-probe
probe_job=mitstack-metadata-probe
max_lines=500

fail() {
  echo "mitstack-report: $*" >&2
  exit 1
}

[ -r "$host_dir/host.tar" ] || fail "mitstack-host has left no host.tar in $host_dir yet"
# Three missed collections mean the host evidence no longer describes the node.
[ -n "$(find "$host_dir/host.tar" -mmin -15)" ] ||
  fail "host.tar in $host_dir is older than 15 minutes, so mitstack-host has stopped collecting"

umask 077
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
tar -xf "$host_dir/host.tar" -C "$work_dir" || fail "host.tar in $host_dir is not a tar archive"

# kube runs one kubectl read with this pod's service account, leaving
# <name>.out, .err and .status.
kube() {
  name=$1
  shift
  kubectl "$@" --request-timeout=10s > "$work_dir/$name.out" 2> "$work_dir/$name.err" ||
    echo "$?" > "$work_dir/$name.status"
}
made_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kube nodes get nodes -o json
kube argocd-pods get pods -n argocd -o json
kube cilium-pods get pods -n kube-system -l app.kubernetes.io/part-of=cilium -o json
kube jobs get jobs -n kube-system -o json
kube helmcharts get helmcharts.helm.cattle.io -n kube-system -o json
kube applications get applications.argoproj.io -n argocd -o json
kube app-projects get appprojects.argoproj.io -n argocd -o json
kube namespaces get namespaces -o json
kube argocd-memory get --raw /apis/metrics.k8s.io/v1beta1/namespaces/argocd/pods
kube cilium-memory get --raw \
  '/apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods?labelSelector=app.kubernetes.io%2Fpart-of%3Dcilium'
kube jwks get --raw /openid/v1/jwks
kube upgrade-plans get plans.upgrade.cattle.io -n system-upgrade -o json
kube upgrade-jobs get jobs -n system-upgrade -o json
kube argocd-services get services -n argocd -o json
kube argocd-ingresses get ingresses -n argocd -o json
kube default-deny get networkpolicies -A --field-selector metadata.name=mitstack-default-deny -o json
kube certificates get certificates.cert-manager.io -A -o json
kube challenges get challenges.acme.cert-manager.io -A -o json
kube probe-pods get pods -n "$probe_ns" -l "job-name=$probe_job" -o json
kube probe-log logs -n "$probe_ns" -l "job-name=$probe_job" --tail=100

# -k accepts Argo CD's self-signed in-cluster certificate.
argocd_paths='/api/v1/session/userinfo /api/v1/account /api/v1/applications
/api/v1/applicationsets /api/v1/certificates /api/v1/clusters /api/v1/gpgkeys
/api/v1/notifications/services /api/v1/notifications/templates
/api/v1/notifications/triggers /api/v1/projects /api/v1/repocreds
/api/v1/repositories /api/v1/settings /api/v1/settings/plugins
/api/v1/write-repocreds /api/v1/write-repositories'
n=0
for path in $argocd_paths; do
  n=$((n + 1))
  answer=$(curl -q -sS -k --proto '=https' --connect-timeout 1 --max-time 5 \
    --max-filesize 65536 -o "$work_dir/argocd-$n.body" -w '%{http_code} %{size_download}' \
    "https://argocd-server.argocd.svc:443$path" 2> /dev/null) && exit_status=0 || exit_status=$?
  printf '%s %s %s %s\n' "$n" "$path" "$exit_status" "$answer" >> "$work_dir/argocd-routes"
done

# python3 writes no header, and exits non-zero, without a usable token.
python3 - "$token_file" "$work_dir" "$max_lines" "$made_at" <<'PY' || exit 1
import base64
import json
import os
import sys
import time

token_path, work, max_lines, made_at = sys.argv[1:5]
os_release, cloud_init, reuse_path = work + "/os-release", work + "/cloud-init-output.log", work + "/enrolment-reuse.json"
state_dir, uu_log, reboot_path = work + "/state", work + "/unattended-upgrades.log", work + "/reboot-required"
try:
    with open(token_path, "rb") as f:
        token = f.read().decode("utf-8").rstrip("\n")
except (OSError, ValueError):
    sys.exit("mitstack-report: cannot read the report token")
if not token or "\n" in token or "\r" in token:
    sys.exit("mitstack-report: the report token is empty or not one line")


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


# text decodes bytes without the NULs the platform refuses.
def text(data, errors="replace"):
    return data.decode("utf-8", errors).replace("\0", "")


# tail is the newest of a file's last max_lines lines whose JSON text fits
# in budget bytes.
def tail(path, max_lines, budget):
    kept = []
    for line in reversed(text(read(path)).splitlines(True)[-max_lines:]):
        budget -= len(json.dumps(line)) - 2
        if budget < 0:
            break
        kept.append(line)
    return "".join(reversed(kept))


# clip is the start of data, or its end, within limit bytes of JSON text.
def clip(data, limit, from_end=False):
    s = text(data[-limit:] if from_end else data[:limit], "ignore")
    kept, used = [], 0
    for ch in reversed(s) if from_end else s:
        used += len(json.dumps(ch)) - 2
        if used > limit:
            break
        kept.append(ch)
    if from_end:
        kept.reverse()
    return "".join(kept)


# bounded keeps entries from the first while their JSON text fits in budget
# bytes, so a read of any size stays a list of whole entries.
def bounded(entries, budget):
    kept = []
    for e in entries:
        budget -= len(json.dumps(e)) + 2
        if budget < 0:
            break
        kept.append(e)
    return kept


# kubectl is the field a read fills: what build makes of its output, or the
# exit status and the newest err_limit bytes of stderr of a call that
# failed, or exit status 0 and why when the output is not what build reads.
def kubectl(name, what, build, err_limit=4096):
    status = read(work + "/" + name + ".status").strip()
    if status:
        return {"exitStatus": int(status), "stderr": clip(read(work + "/" + name + ".err"), err_limit, True)}
    try:
        return build(read(work + "/" + name + ".out"))
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return {"exitStatus": 0, "stderr": "k3s kubectl exited 0, and its output is not the " + what + " this report reads"}


def items(raw):
    found = json.loads(raw)["items"]
    if not isinstance(found, list):
        raise TypeError("items is not a list")
    return found


def ready_condition(item):
    for c in (item.get("status") or {}).get("conditions") or []:
        if c.get("type") == "Ready":
            return c
    return None


def ready(item):
    return (ready_condition(item) or {}).get("status")


def node(n):
    return {
        "name": n["metadata"]["name"],
        "providerID": n["spec"].get("providerID"),
        "taints": n["spec"].get("taints", []),
        "kubeletVersion": n["status"]["nodeInfo"]["kubeletVersion"],
        "ready": ready(n),
        "capacity": n["status"].get("capacity"),
        "allocatable": n["status"].get("allocatable"),
    }


# pod's imageID is null until the container's status reports one.
def pod(p):
    status = p.get("status") or {}
    image_ids = {c.get("name"): c.get("imageID") for c in status.get("containerStatuses") or []}
    return {
        "name": p["metadata"]["name"],
        "phase": status.get("phase"),
        "ready": ready(p),
        "containers": [
            {"name": c.get("name"), "image": c.get("image"), "imageID": image_ids.get(c.get("name"))}
            for c in p["spec"]["containers"]
        ],
    }


def kubernetes():
    nodes = kubectl("nodes", "nodes JSON", lambda raw: bounded(map(node, items(raw)), 4000))
    if isinstance(nodes, dict):
        return nodes
    pods = kubectl("argocd-pods", "pods JSON", lambda raw: bounded(map(pod, items(raw)), 12000))
    if isinstance(pods, dict):
        return pods
    return {"nodes": nodes, "argocdPods": pods}


# A helm-install Job's env carries what k3s installs, and may carry
# credentials, so only these names are read.
HELM_ENV = ("NAME", "VERSION", "REPO", "CHART")


def job(j):
    status = j.get("status") or {}
    return {
        "name": j["metadata"]["name"],
        "creationTimestamp": j["metadata"].get("creationTimestamp"),
        "startTime": status.get("startTime"),
        "completionTime": status.get("completionTime"),
        "succeeded": status.get("succeeded"),
        "failed": status.get("failed"),
    }


def helm_job(j):
    env = {}
    for c in j["spec"]["template"]["spec"]["containers"]:
        for e in c.get("env") or []:
            if e.get("name") in HELM_ENV and isinstance(e.get("value"), str):
                env[e["name"]] = e["value"]
    return dict(job(j), env=env)


def helm_jobs(raw):
    jobs = (j for j in items(raw) if j["metadata"]["name"].startswith("helm-install-"))
    return bounded(map(helm_job, jobs), 6000)


def helm_chart(c):
    spec = c.get("spec") or {}
    return {
        "name": c["metadata"]["name"],
        "chart": spec.get("chart"),
        "version": spec.get("version"),
        "jobName": (c.get("status") or {}).get("jobName"),
    }


CONDITION_MESSAGE_LIMIT = 512

# application keeps the newest ten history entries, oldest first as Argo CD
# keeps them.
def application(a):
    status = a.get("status") or {}
    sync = status.get("sync") or {}
    history = status.get("history") or []
    return {
        "name": a["metadata"]["name"],
        "syncStatus": sync.get("status"),
        "syncRevision": sync.get("revision"),
        "healthStatus": (status.get("health") or {}).get("status"),
        "operationPhase": (status.get("operationState") or {}).get("phase"),
        "reconciledAt": status.get("reconciledAt"),
        "conditions": [{
            "type": c.get("type"),
            "message": clip((c.get("message") or "").encode(), CONDITION_MESSAGE_LIMIT),
        } for c in status.get("conditions") or []],
        "history": [{
            "id": h.get("id"),
            "revision": h.get("revision"),
            "deployedAt": h.get("deployedAt"),
            "targetRevision": (h.get("source") or {}).get("targetRevision"),
            "chart": (h.get("source") or {}).get("chart"),
        } for h in history[-10:]],
    }


def repository_secret(s):
    meta, data = s["metadata"], s.get("data") or {}
    secret = {"name": meta["name"], "secretType": (meta.get("labels") or {}).get("argocd.argoproj.io/secret-type", "")}
    for key in ("project", "url"):
        secret[key] = text(base64.b64decode(data[key], validate=True)) if key in data else ""
    return secret


def app_project(p):
    return {"name": p["metadata"]["name"], "sourceRepos": (p.get("spec") or {}).get("sourceRepos") or []}


def pod_security(n):
    meta = n["metadata"]
    return {"name": meta["name"], "enforce": (meta.get("labels") or {}).get("pod-security.kubernetes.io/enforce")}


# subscription_resources reads the table's rows, the namespace first for a
# namespaced object, then kind/name, and the subscription label last, and
# refuses a row in any other shape. A namespace's own row starts at its
# kind/name, so its namespace is null.
def subscription_resources(raw):
    for line in text(raw).splitlines():
        cols = line.split()
        if not cols:
            continue
        namespace = None
        if "/" not in cols[0]:
            namespace, cols = cols[0], cols[1:]
        if len(cols) < 2 or "/" not in cols[0]:
            raise ValueError("not a row of the labelled objects table")
        kind, name = cols[0].split("/", 1)
        yield {"namespace": namespace, "kind": kind, "name": name, "subscription": cols[-1]}


# cloudnative_pg keeps what the platform observes of a CloudNativePG object:
# a Cluster's phase and instances, a Database's or DatabaseRole's applied
# flag and message.
def cloudnative_pg(o):
    meta, status = o["metadata"], o.get("status") or {}
    entry = {
        "namespace": meta.get("namespace"),
        "kind": o["kind"],
        "name": meta["name"],
        "subscription": (meta.get("labels") or {}).get("mitstack.dev/subscription"),
    }
    if o["kind"] == "Cluster":
        entry.update(phase=status.get("phase"), instances=status.get("instances"), readyInstances=status.get("readyInstances"))
    else:
        entry.update(applied=status.get("applied"), message=clipped_message(status.get("message")))
    return plain(entry)


def pod_memory(m):
    return {
        "name": m["metadata"]["name"],
        "timestamp": m.get("timestamp"),
        "window": m.get("window"),
        "containers": [{"name": c.get("name"), "memory": (c.get("usage") or {}).get("memory")} for c in m.get("containers") or []],
    }


# command is the exit status and the start of the output a run left, at
# most limit bytes of JSON text.
def command(name, limit):
    status = read(work + "/" + name + ".status").strip()
    return {"exitStatus": int(status) if status else 0, "output": clip(read(work + "/" + name + ".out"), limit)}


def kubelet(raw):
    config = json.loads(raw)["kubeletconfig"]
    found = {k: config.get(k) for k in ("evictionHard", "kubeReserved", "systemReserved")}
    if len(json.dumps(found)) > 4096:
        raise ValueError("the kubelet settings are past 4096 bytes")
    return found


# plain drops the NULs from every string in a parsed JSON value.
def plain(v):
    if isinstance(v, str):
        return v.replace("\0", "")
    if isinstance(v, list):
        return [plain(x) for x in v]
    if isinstance(v, dict):
        return {plain(k): plain(x) for k, x in v.items()}
    return v


# plan keeps the conditions, since they carry why a Plan did not apply.
def plan(p):
    spec, status = p.get("spec") or {}, p.get("status") or {}
    return plain({
        "name": p["metadata"]["name"],
        "channel": spec.get("channel"),
        "version": spec.get("version"),
        "window": spec.get("window"),
        "latestVersion": status.get("latestVersion"),
        "conditions": status.get("conditions"),
    })


# kept is a JSON object state_dir keeps as it was written, or why the report
# cannot carry it, or None before the first write; limit bounds the file and
# an eighth more its JSON text.
def kept(name, limit):
    path = state_dir + "/" + name
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            return {"unreadable": "%s is past %d bytes" % (name, limit)}
        check = plain(json.loads(data))
    except (OSError, ValueError) as e:
        return {"unreadable": clip(("%s is not readable JSON: %s" % (name, e)).encode(), 1000)}
    if not isinstance(check, dict):
        return {"unreadable": name + " is not a JSON object"}
    if len(json.dumps(check)) > limit + limit // 8:
        return {"unreadable": "%s is past %d bytes of JSON text" % (name, limit + limit // 8)}
    return check


def bounded_part(name, what, build, limit):
    return kubectl(name, what, build, limit - 48)


def reboot_required():
    try:
        modified = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.stat(reboot_path).st_mtime))
    except OSError:
        modified = None
    return {"exists": modified is not None, "modifiedAt": modified, "packages": clip(read(reboot_path + ".pkgs"), 1024)}


# logged_in is the loggedIn boolean of a 200 userinfo answer that is a JSON
# object, and None for any other answer, so no other response text is kept.
def logged_in(status, body_path):
    if status != 200:
        return None
    try:
        answer = json.loads(read(body_path))
    except (ValueError, RecursionError):
        return None
    flag = answer.get("loggedIn") if isinstance(answer, dict) else None
    return flag if isinstance(flag, bool) else None


# argocd_route is one line of argocd-routes: the path with its HTTP status
# and body size, or status 0 and the curl exit status of a probe that failed.
def argocd_route(line):
    fields = line.split()
    number, path, exit_status = fields[:3]
    entry = {"path": path, "status": 0, "bytes": 0}
    if exit_status != "0":
        entry["error"] = "curl exit " + exit_status
    else:
        entry["status"], entry["bytes"] = int(fields[3]), int(fields[4])
    if path == "/api/v1/session/userinfo":
        entry["loggedIn"] = logged_in(entry["status"], work + "/argocd-" + number + ".body")
    return entry


def argocd_routes():
    return [argocd_route(line) for line in text(read(work + "/argocd-routes")).splitlines()]


def argocd_service(s):
    return {"name": s["metadata"]["name"], "type": (s.get("spec") or {}).get("type")}


def argocd():
    return {
        "routes": argocd_routes(),
        "services": kubectl("argocd-services", "Services JSON", lambda raw: bounded(map(argocd_service, items(raw)), 4096)),
        "ingresses": kubectl("argocd-ingresses", "Ingresses JSON",
                             lambda raw: bounded(({"name": i["metadata"]["name"]} for i in items(raw)), 4096)),
    }


def default_deny(p):
    meta, spec = p["metadata"], p.get("spec") or {}
    return plain({
        "namespace": meta.get("namespace"),
        "name": meta["name"],
        "podSelector": spec.get("podSelector") or {},
        "policyTypes": spec.get("policyTypes") or [],
        "ingressRules": len(spec.get("ingress") or []),
        "egressRules": len(spec.get("egress") or []),
        "managedBy": (meta.get("labels") or {}).get("app.kubernetes.io/managed-by"),
    })


# APP_CERT_STATE_LIMIT bounds each of the certificate and challenge lists to
# the stderr a failed read keeps, so neither outcome squeezes the journal more.
APP_CERT_STATE_LIMIT = 4096


def in_app_namespace(item):
    return str(item["metadata"].get("namespace") or "").startswith("app-")


def clipped_message(message):
    return clip(message.encode(), CONDITION_MESSAGE_LIMIT) if isinstance(message, str) else None


def certificate(c):
    meta, condition = c["metadata"], ready_condition(c) or {}
    return plain({
        "namespace": meta.get("namespace"),
        "name": meta["name"],
        "status": condition.get("status"),
        "reason": condition.get("reason"),
        "message": clipped_message(condition.get("message")),
    })


# challenge omits spec.token and spec.key; a reason may name the challenge URL, which port 80 serves publicly anyway.
def challenge(c):
    meta, spec, status = c["metadata"], c.get("spec") or {}, c.get("status") or {}
    return plain({
        "namespace": meta.get("namespace"),
        "name": meta["name"],
        "dnsName": spec.get("dnsName"),
        "state": status.get("state"),
        "reason": clipped_message(status.get("reason")),
    })


def app_certificates(raw):
    return bounded(map(certificate, filter(in_app_namespace, items(raw))), APP_CERT_STATE_LIMIT)


def app_challenges(raw):
    return bounded(map(challenge, filter(in_app_namespace, items(raw))), APP_CERT_STATE_LIMIT)


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


# metadata_probe is the probe Job's pod and log once that pod has succeeded.
def metadata_probe():
    try:
        pod = items(read(work + "/probe-pods.out"))[0]
        terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
        result = {
            "checkedAt": terminated["finishedAt"],
            "podCreatedAt": pod["metadata"]["creationTimestamp"],
            "containerStartedAt": terminated["startedAt"],
            "log": clip(read(work + "/probe-log.out"), 4096),
        }
        succeeded = pod["status"]["phase"] == "Succeeded"
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return None
    if not succeeded or not result["log"] or not all(isinstance(v, str) for v in result.values()):
        return None
    return result


try:
    reuse = json.loads(read(reuse_path))
except ValueError:
    reuse = None
try:
    keys = json.loads(read(work + "/enrolment-keys.json"))
except ValueError:
    keys = []
rows = kubectl("subscription-resources", "labelled objects table", lambda raw: list(subscription_resources(raw)))
labelled = bounded(rows, 8192) if isinstance(rows, list) else rows
body = {
    "bootId": text(read(work + "/boot_id")).strip(),
    "madeAt": made_at,
    "journal": "",
    "osRelease": clip(read(os_release), 4096),
    "cloudInit": tail(cloud_init, 300, 24000),
    "kubernetes": kubernetes(),
    "ciliumPods": kubectl("cilium-pods", "pods JSON", lambda raw: bounded(map(pod, items(raw)), 12000)),
    "helmInstallJobs": kubectl("jobs", "Jobs JSON", helm_jobs),
    "helmCharts": kubectl("helmcharts", "HelmCharts JSON", lambda raw: bounded(map(helm_chart, items(raw)), 4000)),
    "applications": kubectl("applications", "Applications JSON", lambda raw: bounded(map(application, items(raw)), 24000)),
    "repositorySecrets": kubectl("secrets", "Secrets JSON", lambda raw: bounded(map(repository_secret, items(raw)), 4000)),
    "appProjects": kubectl("app-projects", "AppProjects JSON", lambda raw: bounded(map(app_project, items(raw)), 4096)),
    "podMemory": {
        "argocd": kubectl("argocd-memory", "pod metrics JSON", lambda raw: bounded(map(pod_memory, items(raw)), 6000)),
        "cilium": kubectl("cilium-memory", "pod metrics JSON", lambda raw: bounded(map(pod_memory, items(raw)), 6000)),
    },
    "podSecurity": kubectl("namespaces", "namespaces JSON", lambda raw: bounded(map(pod_security, items(raw)), 4096)),
    "subscriptionResources": labelled,
    "subscriptionResourcesComplete": isinstance(rows, list) and len(labelled) == len(rows),
    "cloudNativePG": kubectl("cloudnative-pg", "CloudNativePG objects JSON", lambda raw: bounded(map(cloudnative_pg, items(raw)), 4096)),
    "jwks": kubectl("jwks", "key set JSON", lambda raw: json.loads(raw * (len(raw) <= 4096))),
    "admission": kubectl("admission-fixtures", "ConfigMap JSON", lambda raw: json.loads(read(work + "/admission.json"))),
    "defaultDenyPolicies": kubectl("default-deny", "NetworkPolicies JSON", lambda raw: bounded(map(default_deny, items(raw)), 4096)),
    "certificates": kubectl("certificates", "Certificates JSON", app_certificates),
    "challenges": kubectl("challenges", "Challenges JSON", app_challenges),
    "podSecurityDryRun": command("dry-run", 8192),
    "hardening": {
        "secretsEncryption": command("secrets-encryption", 2048),
        "ciliumStatus": command("cilium-status", 4096),
        "hubbleObserve": command("hubble-observe", 8192),
        "listeners": command("listeners", 8192),
        "sshUnits": command("ssh-units", 1024),
        "metadataGuard": command("metadata-guard", 2048),
        "kubelet": kubectl("configz", "kubelet configz JSON", kubelet),
        "metadataProbe": metadata_probe(),
    },
    "patching": {
        "check": kept("patch-check.json", 4096),
        "autoUpgradeUnits": command("os-patch-units", 976),
        "unattendedUpgradesLog": tail(uu_log, 1000, 3070),
        "rebootRequired": reboot_required(),
        "kured": {
            "current": bounded_part("kured-log", "kured log", lambda raw: clip(raw, 4094, True), 4096),
            "previous": bounded_part("kured-previous", "kured log", lambda raw: clip(raw, 4094, True), 4096),
        },
        "upgradePlans": {
            "plans": bounded_part("upgrade-plans", "Plans JSON", lambda raw: bounded(map(plan, items(raw)), 1536), 1536),
            "jobs": bounded_part("upgrade-jobs", "Jobs JSON", lambda raw: bounded((plain(job(j)) for j in items(raw)), 1536), 1536),
        },
    },
    "argocd": argocd(),
    "securityScans": {
        "runner": command("scan", 2048),
        "lastRun": kept("scan-run.json", 2048),
        "kubeBench": kept("kube-bench.json", 16384),
        "kubescape": kept("kubescape.json", 16384),
    },
    "dedicatedServer": kept("dedicated-server.json", 2048),
    "enrolment": {k: "<redacted>" for k in keys},
    "enrolmentReuse": reuse,
}
# The journal takes what room the other fields leave under 256 KiB.
body["journal"] = tail(work + "/journal", int(max_lines), min(90000, 262143 - len(json.dumps(body))))


write_private(work + "/headers", "Authorization: Bearer " + token + "\n")
write_private(work + "/body", json.dumps(body))
PY

status=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 20 \
  -X POST -H @"$work_dir/headers" -H 'Content-Type: application/json' \
  --data-binary @"$work_dir/body" -o /dev/null -w '%{http_code}' \
  "$report_url") || status=000
case $status in
  2[0-9][0-9]) exit 0 ;;
  *) fail "the platform did not take the report: HTTP $status" ;;
esac
