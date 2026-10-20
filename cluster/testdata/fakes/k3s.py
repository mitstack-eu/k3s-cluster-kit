import json
import os
import re
import sys
import time
from urllib.parse import parse_qs

ADMISSION_NS = "mitstack-admission-probe"
# Each namespace whose admission-fixtures ConfigMap the node dry-runs, with the answer that holds it.
FIXTURE_READS = {ADMISSION_NS: "admissionFixtures", "mitstack-node": "nodeAdmissionFixtures"}
called_at = time.time()
config_path, args_path = sys.argv[1], sys.argv[2]
argv = sys.argv[3:]
first_call = not os.path.exists(args_path)
with open(args_path + ".times", "a") as f:
    f.write(repr(called_at) + "\n")
with open(args_path, "a") as f:
    f.write(" ".join(argv).replace("\n", "\\n") + "\n")
with open(args_path + ".jsonl", "a") as f:
    f.write(json.dumps(argv) + "\n")
with open(config_path) as f:
    cfg = json.load(f)
if first_call:
    time.sleep(cfg["firstCallDelay"])


def emit(answer):
    sys.stdout.buffer.write(answer.get("stdout", "").encode("utf-8"))
    sys.stderr.buffer.write(answer.get("stderr", "").encode("utf-8"))
    sys.exit(answer.get("exit", 0))


def fail(message, code=1):
    emit({"stderr": message + "\n", "exit": code})


if argv in (["--version"], ["-v"], ["version"]):
    emit(cfg["version"])

if argv[:1] == ["secrets-encrypt"]:
    if argv[1:] != ["status"]:
        fail("k3s secrets-encrypt: this fake answers only status", 2)
    emit(cfg["secretsEncrypt"])

if not argv or argv[0] != "kubectl":
    fail("k3s: no such command " + (argv[0] if argv else ""), 2)

VALUE_FLAGS = {
    "-n": "ns", "--namespace": "ns", "-l": "selector", "--selector": "selector",
    "-o": "output", "--output": "output", "-L": "columns", "--label-columns": "columns",
    "--raw": "raw", "--sort-by": "sort", "--template": "template", "--field-selector": "fields",
    "--request-timeout": "", "--chunk-size": "", "--context": "", "--kubeconfig": "kubeconfig",
    "-c": "container", "--container": "container", "--image": "image", "--restart": "restart", "-f": "file", "--filename": "file",
    "--for": "for", "--timeout": "timeout",
    "--tail": "", "--limit-bytes": "", "--since": "", "--since-time": "",
}
opts = {"columns": []}
flags = []
positional = []
command = None
args = argv[1:]
i = 0
while i < len(args):
    a = args[i]
    key = value = None
    if a == "--":
        command = args[i + 1:]
        break
    if a in VALUE_FLAGS and i + 1 < len(args):
        key, value = VALUE_FLAGS[a], args[i + 1]
        i += 2
    elif a.startswith("--") and "=" in a and a.split("=", 1)[0] in VALUE_FLAGS:
        name, value = a.split("=", 1)
        key = VALUE_FLAGS[name]
        i += 1
    elif len(a) > 2 and a[:2] in ("-n", "-l", "-o", "-L"):
        key, value = VALUE_FLAGS[a[:2]], a[2:].lstrip("=")
        i += 1
    else:
        (flags if a.startswith("-") else positional).append(a)
        i += 1
        continue
    if key == "columns":
        opts["columns"] += [c for c in value.split(",") if c]
    elif key:
        opts[key] = value


def matches(selector, item):
    labels = (item.get("metadata") or {}).get("labels") or {}
    for term in selector.split(","):
        term = term.strip()
        if not term:
            continue
        if "!=" in term:
            k, v = term.split("!=", 1)
            ok = labels.get(k) != v
        elif "=" in term:
            k, v = term.replace("==", "=").split("=", 1)
            ok = labels.get(k) == v
        elif term.startswith("!"):
            ok = term[1:] not in labels
        else:
            ok = term in labels
        if not ok:
            return False
    return True


def long_image(i):
    return "registry.example.com/%s/image-%05d:v1.0.0-%s" % ("p" * 120, i, "t" * 80)


def padded(prefix, i, fill, n):
    return "%s-%05d-%s" % (prefix, i, fill * n)


def listing(items):
    return {"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": ""}, "items": items}


def namespace_doc(name, labels):
    all_labels = {"kubernetes.io/metadata.name": name}
    all_labels.update(labels)
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": all_labels, "creationTimestamp": "2026-10-01T09:16:02Z"},
            "spec": {"finalizers": ["kubernetes"]}, "status": {"phase": "Active"}}


# generate builds the answer far past what one report can carry: count entries with long names.
def generate(spec):
    kind, n = spec["kind"], spec["count"]
    if kind == "admissionFixtures":
        return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "admission-fixtures", "namespace": ADMISSION_NS},
                "data": {"rule-%05d" % i: "apiVersion: v1\n# " + "f" * 10000 + "\n" for i in range(n)}}
    items = []
    for i in range(n):
        if kind == "pods":
            containers, statuses = [], []
            for c in range(3):
                name = "container-%d-%s" % (c, "c" * 40)
                containers.append({"name": name, "image": long_image(i * 3 + c)})
                statuses.append({"name": name, "image": long_image(i * 3 + c),
                                 "imageID": "registry.example.com/image-%05d@sha256:%064x" % (i * 3 + c, i * 3 + c)})
            items.append({"metadata": {"name": padded(spec["prefix"], i, "x", 40), "labels": spec["labels"]},
                          "spec": {"containers": containers},
                          "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                                     "containerStatuses": statuses}})
        elif kind == "metrics":
            containers = [{"name": "container-%d-%s" % (c, "c" * 40), "usage": {"cpu": "123456789n", "memory": "%dKi" % (100000 + i)}}
                          for c in range(3)]
            items.append({"metadata": {"name": padded(spec["prefix"], i, "x", 40), "labels": spec["labels"]},
                          "timestamp": "2026-10-01T09:44:51Z", "window": "10.512s", "containers": containers})
        elif kind in ("helmJobs", "helmCharts", "repositorySecrets"):
            name = padded("chart", i, "n", 40)
            version = "1.0.0-" + "v" * 60
            if kind == "helmJobs":
                env = [{"name": "NAME", "value": name}, {"name": "VERSION", "value": version},
                       {"name": "REPO", "value": "https://charts.example.com/" + "r" * 100}, {"name": "CHART", "value": name}]
                items.append({"metadata": {"name": "helm-install-" + name, "creationTimestamp": "2026-10-01T09:16:02Z"},
                              "spec": {"template": {"spec": {"containers": [{"name": "helm", "image": long_image(i), "env": env}]}}},
                              "status": {"startTime": "2026-10-01T09:16:02Z", "completionTime": "2026-10-01T09:17:41Z", "succeeded": 1, "failed": 3}})
            elif kind == "helmCharts":
                items.append({"metadata": {"name": name},
                              "spec": {"chart": name, "repo": "https://charts.example.com/", "version": version},
                              "status": {"jobName": "helm-install-" + name}})
            else:
                items.append({"type": "Opaque",
                              "metadata": {"name": padded("repository", i, "s", 200), "labels": {"argocd.argoproj.io/secret-type": "repository"}},
                              "data": {"password": cfg["secretB64"]}})
        elif kind == "applications":
            history = [{"id": h, "revision": "%040x" % (i * 40 + h) + "r" * 160, "deployedAt": "2026-10-01T09:30:00Z",
                        "source": {"repoURL": "https://charts.example.com/", "chart": "chart-%05d" % i, "targetRevision": "9" * 120}}
                       for h in range(40)]
            items.append({"metadata": {"name": padded("application", i, "a", 40)},
                          "status": {"sync": {"status": "Synced", "revision": "f" * 200}, "health": {"status": "Healthy"},
                                     "operationState": {"phase": "Succeeded"}, "reconciledAt": "2026-10-01T09:45:12Z", "history": history,
                                     "conditions": [{"type": "SharedResourceWarning", "message": "short-%05d" % i, "lastTransitionTime": "2026-10-01T09:45:00Z"},
                                                    {"type": "ComparisonError", "message": "comparison-%05d-" % i + "m" * 700, "lastTransitionTime": "2026-10-01T09:45:01Z"}]}})
        elif kind == "services":
            name, ip = ("argocd-server", "10.43.77.20") if i == 0 else (padded("service", i, "s", 60), "10.43.%d.%d" % (i // 250 % 250, i % 250 + 1))
            items.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": "argocd"},
                          "spec": {"type": "ClusterIP", "clusterIP": ip,
                                   "ports": [{"name": "https", "port": 443, "protocol": "TCP"}]}})
        elif kind == "ingresses":
            items.append({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": padded("ingress", i, "g", 60), "namespace": "argocd"},
                          "spec": {"rules": [{"host": "argocd-%05d.example.com" % i}]}})
        elif kind == "namespaces":
            items.append(namespace_doc(padded("namespace", i, "n", 40), {
                "pod-security.kubernetes.io/enforce": "restricted", "mitstack.dev/subscription": "%08x-0000-4000-8000-%012x" % (i, i)}))
        elif kind == "subscriptionObjects":
            api, k, extra = [("apps/v1", "Deployment", {}), ("v1", "ConfigMap", {"data": {"APP_ENV": "production"}}),
                             ("v1", "Secret", {"type": "Opaque", "data": {"password": cfg["secretB64"]}}),
                             ("argoproj.io/v1alpha1", "AppProject", {})][i % 4]
            name = padded("object", i, "o", 60)
            obj = {"apiVersion": api, "kind": k,
                   "metadata": {"name": name, "namespace": padded("namespace", i % 50, "n", 40),
                                "labels": {"app.kubernetes.io/name": name, "mitstack.dev/subscription": "%08x-0000-4000-8000-%012x" % (i, i)},
                                "creationTimestamp": "2026-10-01T09:16:02Z"}}
            obj.update(extra)
            items.append(obj)
        elif kind == "plans":
            items.append({"metadata": {"name": padded("plan", i, "p", 40)}, "spec": {
                "channel": "https://update.k3s.io/v1-release/channels/v1.36", "version": "v1.36.5+k3s1",
                "window": {"days": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
                           "startTime": "03:00", "endTime": "05:00", "timeZone": "UTC"}},
                "status": {"latestVersion": "v1.36.5-k3s1", "conditions": [
                    {"type": "LatestResolved", "status": "True", "reason": "Version", "lastUpdateTime": "2026-10-08T03:00:11Z"}]}})
        elif kind == "networkPolicies":
            items.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                          "metadata": {"name": "mitstack-default-deny", "namespace": padded("namespace", i, "n", 40),
                                       "labels": {"app.kubernetes.io/managed-by": "kyverno"}},
                          "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}})
        elif kind == "cloudNativePGObjects":
            items.append({"apiVersion": "postgresql.cnpg.io/v1", "kind": "Database",
                          "metadata": {"name": padded("database", i, "d", 60), "namespace": padded("namespace", i % 50, "n", 40),
                                       "labels": {"mitstack.dev/subscription": "%08x-0000-4000-8000-%012x" % (i, i)}},
                          "status": {"applied": False, "message": "database-%05d-" % i + "m" * 700}})
        elif kind == "upgradeJobs":
            items.append({"metadata": {"name": padded("apply-plan", i, "j", 40), "creationTimestamp": "2026-10-08T03:00:12Z"},
                          "spec": {"template": {"spec": {"containers": [{"name": "upgrade", "image": long_image(i)}]}}},
                          "status": {"startTime": "2026-10-08T03:00:12Z", "completionTime": "2026-10-08T03:02:40Z", "succeeded": 1}})
    if kind == "metrics":
        return {"kind": "PodMetricsList", "apiVersion": "metrics.k8s.io/v1beta1", "metadata": {}, "items": items}
    return listing(items)


def answer_doc(read):
    if read in cfg["generate"]:
        return generate(cfg["generate"][read])
    return json.loads(cfg["answers"][read])


def answer_for(read, selector):
    if read in cfg["failures"]:
        emit(cfg["failures"][read])
    if read in cfg["printing"]:
        emit({"stdout": cfg["printing"][read]})
    doc = answer_doc(read)
    if selector:
        doc["items"] = [item for item in doc.get("items", []) if matches(selector, item)]
    return doc


PROBE_NS = "mitstack-metadata-probe"
PROBE_SELECTOR = "job-name=mitstack-metadata-probe"
probe = cfg["probe"]
probe_exists = probe["phase"] != ""


# target reads TYPE NAME or TYPE/NAME as [TYPE, NAME].
def target(words):
    if len(words) == 1 and "/" in words[0]:
        return words[0].split("/", 1)
    return words


def probe_pod():
    if probe["phase"] in ("Succeeded", "Failed"):
        state = {"terminated": {
            "exitCode": 0 if probe["phase"] == "Succeeded" else 1,
            "reason": "Completed" if probe["phase"] == "Succeeded" else "Error",
            "startedAt": probe["startedAt"], "finishedAt": probe["finishedAt"],
        }}
    else:
        state = {"running": {"startedAt": probe["startedAt"]}}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "probe", "namespace": PROBE_NS, "creationTimestamp": probe["createdAt"]},
        "spec": {"restartPolicy": "Never", "containers": [{"name": "probe", "image": probe["image"]}]},
        "status": {
            "phase": probe["phase"], "startTime": probe["createdAt"],
            "containerStatuses": [{"name": "probe", "ready": False, "restartCount": 0,
                                   "image": probe["image"], "imageID": probe["image"], "state": state}],
        },
    }


# jsonpath fills each {.a.b[0].c} of template from doc, as kubectl's
# -o jsonpath does for plain field paths.
def jsonpath(doc, template):
    def lookup(expr):
        v = doc
        for name, index in re.findall(r"\.([A-Za-z0-9_-]+)|\[([0-9]+)\]", expr):
            if name:
                v = v.get(name) if isinstance(v, dict) else None
            else:
                v = v[int(index)] if isinstance(v, list) and int(index) < len(v) else None
        if v is None:
            return ""
        return v if isinstance(v, str) else json.dumps(v)
    return re.sub(r"\{([^}]*)\}", lambda m: lookup(m.group(1)), template)


verb = positional[0] if positional else ""
if verb == "label":
    if "--dry-run=server" not in flags:
        fail("error: this fake k3s answers kubectl label only as --dry-run=server")
    if "label" in cfg["failures"]:
        emit(cfg["failures"]["label"])
    emit(cfg["label"])
if verb == "exec":
    if (opts.get("ns") != "kube-system" or target(positional[1:]) not in (["ds", "cilium"], ["daemonset", "cilium"], ["daemonsets", "cilium"])
            or opts.get("container") != "cilium-agent" or not command):
        fail("error: this fake k3s execs only into the cilium-agent container of ds/cilium in kube-system")
    key = " ".join(command)
    if key not in cfg["exec"]:
        fail("OCI runtime exec failed: this fake cilium-agent runs only " + json.dumps(sorted(cfg["exec"])), 126)
    emit(cfg["exec"][key])
if verb == "logs" and opts.get("ns") == "kube-system":
    if target(positional[1:]) not in (["ds", "kured"], ["daemonset", "kured"], ["daemonsets", "kured"]):
        fail("error: this fake k3s answers kubectl logs in kube-system only for ds/kured")
    previous = any(f in ("-p", "--previous", "--previous=true") for f in flags)
    read = "kuredPreviousLog" if previous else "kuredLog"
    if read in cfg["failures"]:
        emit(cfg["failures"][read])
    emit({"stdout": cfg["logs"][read]})
if verb == "logs":
    if opts.get("ns") != PROBE_NS or opts.get("selector") != PROBE_SELECTOR:
        fail("error: this fake k3s answers kubectl logs only for ds/kured and the pods of " + PROBE_SELECTOR)
    if "probeLog" in cfg["failures"]:
        emit(cfg["failures"]["probeLog"])
    emit({"stdout": probe["log"]} if probe_exists else {"stderr": "No resources found in " + PROBE_NS + " namespace.\n"})
if verb == "apply":
    if "--dry-run=server" not in flags or opts.get("ns") not in FIXTURE_READS or opts.get("file") != "-":
        fail("error: this fake k3s applies only with --dry-run=server -n " + " or -n ".join(FIXTURE_READS) + " -f -")
    manifest = sys.stdin.buffer.read().decode("utf-8")
    fixtures = answer_doc(FIXTURE_READS[opts["ns"]]).get("data") or {}
    rule = next((k for k, v in fixtures.items() if v == manifest), None)
    if rule is None:
        fail("error: this fake k3s applies only a manifest the ConfigMap admission-fixtures holds")
    if rule in cfg["applies"]:
        emit(cfg["applies"][rule])
    if "admissionFixtures" in cfg["generate"]:
        emit({"stderr": "Error from server: denied the request: " + "m" * 10000 + "\n", "exit": 1})
    emit({"stdout": "deployment.apps/" + rule + " created (server dry run)\n"})
if verb != "get":
    fail("error: this fake k3s answers only kubectl get, kubectl label --dry-run=server, kubectl apply --dry-run=server, kubectl exec into cilium-agent and the metadata probe")

if (opts.get("ns") in FIXTURE_READS and target(positional[1:]) in (["configmap", "admission-fixtures"], ["configmaps", "admission-fixtures"], ["cm", "admission-fixtures"])
        and opts.get("output") == "json"):
    if FIXTURE_READS[opts["ns"]] not in cfg["answers"] and FIXTURE_READS[opts["ns"]] not in cfg["generate"]:
        fail("Error from server (NotFound): configmaps \"admission-fixtures\" not found")
    emit({"stdout": json.dumps(answer_for(FIXTURE_READS[opts["ns"]], ""))})
if len(positional) == 2 and positional[1] in ("networkpolicies", "networkpolicy", "netpol") and opts.get("output") == "json":
    if "-A" not in flags and "--all-namespaces" not in flags:
        fail("error: this fake k3s lists NetworkPolicies only across all namespaces")
    doc = answer_for("defaultDenyPolicies", "")
    field, _, wanted = opts.get("fields", "").partition("=")
    if field != "metadata.name" or not wanted:
        fail("error: this fake k3s lists NetworkPolicies only by --field-selector metadata.name=NAME")
    doc["items"] = [o for o in doc["items"] if o["metadata"]["name"] == wanted]
    emit({"stdout": json.dumps(doc)})

CERT_READS = {
    "certificates": "certificates", "certificate": "certificates", "cert": "certificates", "certificates.cert-manager.io": "certificates",
    "challenges": "challenges", "challenge": "challenges", "challenges.acme.cert-manager.io": "challenges",
}
CNPG_READ = "clusters.postgresql.cnpg.io,databases.postgresql.cnpg.io,databaseroles.postgresql.cnpg.io"
if len(positional) == 2 and positional[1] == CNPG_READ:
    if ("-A" not in flags and "--all-namespaces" not in flags) or opts.get("output") != "json":
        fail("error: this fake k3s lists CloudNativePG's objects only across all namespaces as JSON")
    emit({"stdout": json.dumps(answer_for("cloudNativePG", ""))})
if len(positional) == 2 and positional[1] in CERT_READS and opts.get("output") == "json":
    if "-A" not in flags and "--all-namespaces" not in flags:
        fail("error: this fake k3s lists certificates and challenges only across all namespaces")
    emit({"stdout": json.dumps(answer_for(CERT_READS[positional[1]], ""))})

if "raw" in opts:
    path, _, query = opts["raw"].partition("?")
    node = re.match(r"^/api/v1/nodes/([^/]+)/proxy/configz$", path)
    if node:
        if node.group(1) != cfg["nodeName"]:
            fail("Error from server (NotFound): nodes \"" + node.group(1) + "\" not found")
        if "configz" in cfg["failures"]:
            emit(cfg["failures"]["configz"])
        if "configz" in cfg["printing"]:
            emit({"stdout": cfg["printing"]["configz"]})
        emit({"stdout": cfg["configz"]})
    read = cfg["raw"].get(path)
    if read is None:
        fail("Error from server (NotFound): the server could not find the requested resource")
    selector = parse_qs(query).get("labelSelector", [""])[0]
    emit({"stdout": json.dumps(answer_for(read, selector))})

if len(positional) < 2:
    fail("error: you must specify the type of resource to get")
if opts.get("ns") == PROBE_NS:
    if positional[1:] != ["pods"] or opts.get("selector") != PROBE_SELECTOR or opts.get("output") != "json":
        fail("error: this fake k3s answers only the pods of " + PROBE_SELECTOR + " as JSON")
    if "probePods" in cfg["failures"]:
        emit(cfg["failures"]["probePods"])
    emit({"stdout": json.dumps(listing([probe_pod()] if probe_exists else []))})

SUBSCRIPTION_LABEL = "mitstack.dev/subscription"


# SUB_KINDS are the kinds a namespaces or subscription read may name: what
# --show-kind prints, the Kind the objects carry, whether the kind is
# namespaced, the names kubectl takes for it, the columns the API server
# prints before any label column, and each object's cells under them.
SUB_KINDS = [
    ("namespace", "Namespace", False, ("namespace", "namespaces", "ns"), ["STATUS", "AGE"],
     lambda o: [(o.get("status") or {}).get("phase", "Active"), "5d"]),
    ("deployment.apps", "Deployment", True, ("deployment", "deployments", "deploy", "deployment.apps", "deployments.apps"),
     ["READY", "UP-TO-DATE", "AVAILABLE", "AGE"], lambda o: ["1/1", "1", "1", "5d"]),
    ("statefulset.apps", "StatefulSet", True, ("statefulset", "statefulsets", "sts", "statefulset.apps", "statefulsets.apps"),
     ["READY", "AGE"], lambda o: ["1/1", "5d"]),
    ("daemonset.apps", "DaemonSet", True, ("daemonset", "daemonsets", "ds", "daemonset.apps", "daemonsets.apps"),
     ["DESIRED", "CURRENT", "READY", "UP-TO-DATE", "AVAILABLE", "NODE SELECTOR", "AGE"],
     lambda o: ["1", "1", "1", "1", "1", "<none>", "5d"]),
    ("pod", "Pod", True, ("pod", "pods", "po"), ["READY", "STATUS", "RESTARTS", "AGE"],
     lambda o: ["1/1", "Running", "1 (3h ago)", "5d"]),
    ("service", "Service", True, ("service", "services", "svc"), ["TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"],
     lambda o: ["ClusterIP", "10.43.12.7", "<none>", "80/TCP", "5d"]),
    ("ingress.networking.k8s.io", "Ingress", True,
     ("ingress", "ingresses", "ing", "ingress.networking.k8s.io", "ingresses.networking.k8s.io"),
     ["CLASS", "HOSTS", "ADDRESS", "PORTS", "AGE"],
     lambda o: ["traefik", "demo.203-0-113-10.sslip.io", "203.0.113.10", "80, 443", "5d"]),
    ("configmap", "ConfigMap", True, ("configmap", "configmaps", "cm"), ["DATA", "AGE"],
     lambda o: [str(len(o.get("data") or {})), "5d"]),
    ("secret", "Secret", True, ("secret", "secrets"), ["TYPE", "DATA", "AGE"],
     lambda o: [o.get("type", "Opaque"), str(len(o.get("data") or {})), "5d"]),
    ("serviceaccount", "ServiceAccount", True, ("serviceaccount", "serviceaccounts", "sa"), ["SECRETS", "AGE"],
     lambda o: ["0", "5d"]),
    ("role.rbac.authorization.k8s.io", "Role", True,
     ("role", "roles", "role.rbac.authorization.k8s.io", "roles.rbac.authorization.k8s.io"),
     ["CREATED AT"], lambda o: ["2026-10-01T09:16:02Z"]),
    ("rolebinding.rbac.authorization.k8s.io", "RoleBinding", True,
     ("rolebinding", "rolebindings", "rolebinding.rbac.authorization.k8s.io", "rolebindings.rbac.authorization.k8s.io"),
     ["ROLE", "AGE"], lambda o: ["Role/" + o["metadata"]["name"], "5d"]),
    ("networkpolicy.networking.k8s.io", "NetworkPolicy", True,
     ("networkpolicy", "networkpolicies", "netpol", "networkpolicy.networking.k8s.io", "networkpolicies.networking.k8s.io"),
     ["POD-SELECTOR", "AGE"], lambda o: ["<none>", "5d"]),
    ("resourcequota", "ResourceQuota", True, ("resourcequota", "resourcequotas", "quota"), ["AGE", "REQUEST", "LIMIT"],
     lambda o: ["5d", "requests.cpu: 0/2, requests.memory: 0/4Gi", "limits.cpu: 0/4"]),
    ("limitrange", "LimitRange", True, ("limitrange", "limitranges", "limits"), ["CREATED AT"],
     lambda o: ["2026-10-01T09:16:02Z"]),
    ("persistentvolumeclaim", "PersistentVolumeClaim", True, ("persistentvolumeclaim", "persistentvolumeclaims", "pvc"),
     ["STATUS", "VOLUME", "CAPACITY", "ACCESS MODES", "STORAGECLASS", "VOLUMEATTRIBUTESCLASS", "AGE"],
     lambda o: ["Bound", "pvc-0b1c2d3e", "1Gi", "RWO", "local-path", "<unset>", "5d"]),
    ("certificate.cert-manager.io", "Certificate", True,
     ("certificate", "certificates", "cert", "certs", "certificate.cert-manager.io", "certificates.cert-manager.io"),
     ["READY", "SECRET", "AGE"], lambda o: ["True", o["metadata"]["name"], "5d"]),
    ("application.argoproj.io", "Application", True,
     ("application", "applications", "app", "apps", "application.argoproj.io", "applications.argoproj.io"),
     ["SYNC STATUS", "HEALTH STATUS"], lambda o: ["Synced", "Healthy"]),
    ("appproject.argoproj.io", "AppProject", True,
     ("appproject", "appprojects", "appproj", "appprojs", "appproject.argoproj.io", "appprojects.argoproj.io"),
     ["AGE"], lambda o: ["5d"]),
]


def sub_kind(word):
    for k in SUB_KINDS:
        if word.lower() in k[3]:
            return k
    return None


def table(rows):
    widths = [max(len(r[j]) for r in rows) for j in range(len(rows[0]))]
    return "".join("   ".join(cell.ljust(w) for cell, w in zip(r, widths)).rstrip() + "\n" for r in rows)


selector = opts.get("selector", "")
resource_words = [w for w in positional[1].split(",") if w]
named = [sub_kind(w) for w in resource_words]
if SUBSCRIPTION_LABEL in selector or (named and all(k is not None and k[0] == "namespace" for k in named)):
    read = "subscriptionResources" if SUBSCRIPTION_LABEL in selector else "namespaces"
    if read in cfg["failures"]:
        emit(cfg["failures"][read])
    if read in cfg["printing"]:
        emit({"stdout": cfg["printing"][read]})
    for word, k in zip(resource_words, named):
        if k is None:
            fail("error: the server doesn't have a resource type " + json.dumps(word))
    all_ns = any(f in ("-A", "--all-namespaces", "--all-namespaces=true") for f in flags)
    in_ns = opts.get("ns", "default")
    namespace_items = answer_doc("namespaces")["items"]
    object_items = answer_doc("subscriptionResources")["items"] if read == "subscriptionResources" else []
    groups = []
    for k in named:
        if any(g[0] is k for g in groups):
            continue
        if k[2]:
            found = [o for o in object_items if o["kind"] == k[1] and (all_ns or o["metadata"].get("namespace") == in_ns)]
        else:
            found = namespace_items
        groups.append((k, [o for o in found if matches(selector, o)]))
    output = opts.get("output", "")
    everything = [o for _, found in groups for o in found]
    if output == "name":
        emit({"stdout": "".join(k[0] + "/" + o["metadata"]["name"] + "\n" for k, found in groups for o in found)})
    if output not in ("", "wide"):
        emit({"stdout": json.dumps({"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": ""}, "items": everything})})
    if not everything:
        emit({"stderr": "No resources found\n"})
    show_kind = len(groups) > 1 or any(f in ("--show-kind", "--show-kind=true") for f in flags)
    headers = "--no-headers" not in flags and "--no-headers=true" not in flags
    columns = opts["columns"]
    blocks = []
    for k, found in groups:
        if not found:
            continue
        with_ns = all_ns and k[2]
        rows = []
        for o in found:
            meta = o["metadata"]
            labels = meta.get("labels") or {}
            rows.append(([meta.get("namespace", "")] if with_ns else [])
                        + [(k[0] + "/" if show_kind else "") + meta["name"]]
                        + k[5](o) + [labels.get(c, "") for c in columns])
        if headers:
            rows.insert(0, (["NAMESPACE"] if with_ns else []) + ["NAME"] + k[4] + [c.split("/")[-1].upper() for c in columns])
        blocks.append(table(rows))
    emit({"stdout": ("\n" if headers else "").join(blocks)})

KINDS = {
    "nodes": "nodes", "node": "nodes", "no": "nodes",
    "pods": "pods", "pod": "pods", "po": "pods",
    "jobs": "jobs", "job": "jobs", "jobs.batch": "jobs", "job.batch": "jobs",
    "helmcharts": "helmcharts", "helmchart": "helmcharts",
    "helmcharts.helm.cattle.io": "helmcharts", "helmchart.helm.cattle.io": "helmcharts",
    "applications": "applications", "application": "applications", "app": "applications", "apps": "applications",
    "applications.argoproj.io": "applications", "application.argoproj.io": "applications",
    "secrets": "secrets", "secret": "secrets",
    "appprojects": "appprojects", "appproject": "appprojects",
    "appprojects.argoproj.io": "appprojects", "appproject.argoproj.io": "appprojects",
    "plans": "plans", "plan": "plans", "plans.upgrade.cattle.io": "plans", "plan.upgrade.cattle.io": "plans",
    "services": "services", "service": "services", "svc": "services",
    "ingresses": "ingresses", "ingress": "ingresses", "ing": "ingresses",
}
kind = KINDS.get(positional[1].lower())
if kind is None:
    fail("error: the server does not have a resource type " + json.dumps(positional[1]))
ns = opts.get("ns", "default")
READS = {
    ("pods", "argocd"): "argocdPods", ("pods", "kube-system"): "kubeSystemPods",
    ("jobs", "kube-system"): "jobs", ("helmcharts", "kube-system"): "helmcharts",
    ("applications", "argocd"): "applications", ("secrets", "argocd"): "secrets", ("appprojects", "argocd"): "appProjects",
    ("plans", "system-upgrade"): "upgradePlans", ("jobs", "system-upgrade"): "upgradeJobs",
    ("services", "argocd"): "argocdServices", ("ingresses", "argocd"): "argocdIngresses",
}
read = "nodes" if kind == "nodes" else READS.get((kind, ns))
if read is None:
    fail("error: this fake k3s answers " + kind + " only in the namespace the report reads them from, not " + ns)
if read == "argocdServices" and len(positional) > 2:
    # A named Service is read for its cluster IP alone, through -o jsonpath.
    if "argocdClusterIP" in cfg["failures"]:
        emit(cfg["failures"]["argocdClusterIP"])
    if "argocdClusterIP" in cfg["printing"]:
        emit({"stdout": cfg["printing"]["argocdClusterIP"]})
    named_service = [s for s in answer_doc("argocdServices")["items"] if s["metadata"]["name"] == positional[2]]
    if not named_service:
        fail("Error from server (NotFound): services \"" + positional[2] + "\" not found")
    if not opts.get("output", "").startswith("jsonpath="):
        fail("error: this fake k3s answers a named Service only with -o jsonpath")
    emit({"stdout": jsonpath(named_service[0], opts["output"][len("jsonpath="):])})
doc = answer_for(read, opts.get("selector", ""))
output = opts.get("output", "")

if read != "secrets":
    if output.startswith("jsonpath="):
        emit({"stdout": jsonpath(doc, output[len("jsonpath="):])})
    if output != "json":
        fail("error: this fake k3s answers only -o json or -o jsonpath")
    emit({"stdout": json.dumps(doc)})

if output == "name":
    emit({"stdout": "".join("secret/" + s["metadata"]["name"] + "\n" for s in doc["items"])})
if output not in ("", "wide"):
    emit({"stdout": json.dumps(doc)})
if not doc["items"]:
    emit({"stderr": "No resources found in argocd namespace.\n"})
columns = opts["columns"]
rows = []
for s in doc["items"]:
    labels = s["metadata"].get("labels") or {}
    rows.append([s["metadata"]["name"], s.get("type", "Opaque"), str(len(s.get("data") or {})), "5d"]
                + [labels.get(c, "") for c in columns])
if "--no-headers" not in flags and "--no-headers=true" not in flags:
    rows.insert(0, ["NAME", "TYPE", "DATA", "AGE"] + [c.split("/")[-1].upper() for c in columns])
widths = [max(len(r[j]) for r in rows) for j in range(len(rows[0]))]
emit({"stdout": "".join("   ".join(cell.ljust(w) for cell, w in zip(r, widths)).rstrip() + "\n" for r in rows)})
