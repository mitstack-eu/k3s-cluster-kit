#!/bin/sh
# Collects the node report's host evidence and writes it to stdout as a tar
# archive, runs the patch check once its result is an hour old, and starts the
# security scan.
# Usage: sh -c "$(cat collect.sh)" collect <patch check script> <scan script>,
# run by mitstack-host in the host's namespaces.
# It exists because these reads need host root, the admin kubeconfig or the
# host's own tools, which no service account grants.
set -eu

enrolment_dir=${MITSTACK_ENROLMENT_DIR:-/etc/mitstack}
journalctl=${MITSTACK_JOURNALCTL:-journalctl}
os_release=${MITSTACK_OS_RELEASE:-/etc/os-release}
cloud_init_log=${MITSTACK_CLOUD_INIT_LOG:-/var/log/cloud-init-output.log}
k3s=${MITSTACK_K3S:-/usr/local/bin/k3s}
userdata_url=${MITSTACK_USERDATA_URL:-http://169.254.169.254/hetzner/v1/userdata}
enrolment_url=${MITSTACK_ENROLMENT_URL:-https://api.mitstack.dev/v1/cluster-enrolments}
ss=${MITSTACK_SS:-ss}
systemctl=${MITSTACK_SYSTEMCTL:-systemctl}
nft=${MITSTACK_NFT:-nft}
systemd_run=${MITSTACK_SYSTEMD_RUN:-systemd-run}
state_dir=${MITSTACK_STATE_DIR:-/var/lib/mitstack}
uu_log=${MITSTACK_UNATTENDED_UPGRADES_LOG:-/var/log/unattended-upgrades/unattended-upgrades.log}
reboot_required=${MITSTACK_REBOOT_REQUIRED:-/var/run/reboot-required}
dedicated_probe=/usr/local/sbin/mitstack-dedicated-probe
json_file=$enrolment_dir/enrolment.json
reuse_file=$enrolment_dir/enrolment-reuse.json
patch_check=$1
scan=$2

fail() {
  echo "mitstack-collect: $*" >&2
  exit 1
}

[ -r "$json_file" ] || fail "cannot read $json_file, so the node is not enrolled"

umask 077
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"; rm -f "$reuse_file.partial"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work_dir/state"

"$journalctl" -b --no-pager -o short-iso-precise -n 500 \
  _SYSTEMD_UNIT=mitstack-enrol.service + \
  _PID=1 UNIT=mitstack-enrol.service + \
  _PID=1 UNIT=k3s.service + \
  _SYSTEMD_UNIT=mitstack-repo-token.service + \
  _PID=1 UNIT=mitstack-metadata-guard.service + \
  _SYSTEMD_UNIT=mitstack-metadata-guard.service > "$work_dir/journal" ||
  fail "journalctl could not read this boot's journal"

# kube runs one k3s kubectl read, leaving <name>.out, .err and .status.
kube() {
  name=$1
  shift
  "$k3s" kubectl "$@" --request-timeout=10s > "$work_dir/$name.out" 2> "$work_dir/$name.err" ||
    echo "$?" > "$work_dir/$name.status"
}
kube secrets get secrets -n argocd -l argocd.argoproj.io/secret-type -o json
kube subscription-resources get namespaces,deployments,statefulsets,daemonsets,pods,services,ingresses,configmaps,secrets,serviceaccounts,roles,rolebindings,networkpolicies,resourcequotas,limitranges,persistentvolumeclaims,certificates.cert-manager.io,applications.argoproj.io,appprojects.argoproj.io \
  -A -l mitstack.dev/subscription -L mitstack.dev/subscription --show-kind --no-headers
# A read of its own, so a cluster without CloudNativePG's CRDs still files the
# subscription read above.
kube cloudnative-pg get clusters.postgresql.cnpg.io,databases.postgresql.cnpg.io,databaseroles.postgresql.cnpg.io \
  -A -o json
# k3s names the node by its host name.
kube configz get --raw "/api/v1/nodes/$(uname -n)/proxy/configz"
kube kured-log logs -n kube-system ds/kured --tail=200
kube kured-previous logs -n kube-system ds/kured --previous --tail=200
kube admission-fixtures get configmap admission-fixtures -n mitstack-admission-probe -o json
kube node-admission-fixtures get configmap admission-fixtures -n mitstack-node -o json

# run runs one command, leaving <name>.out and, on a failure, .status.
run() {
  name=$1
  shift
  "$@" > "$work_dir/$name.out" 2>&1 || echo "$?" > "$work_dir/$name.status"
}
# A server dry run of the restricted Pod Security level changes nothing, and
# its warnings name the argocd pods that level would not admit.
run dry-run "$k3s" kubectl label --dry-run=server --overwrite namespace argocd \
  pod-security.kubernetes.io/enforce=restricted --request-timeout=10s
run secrets-encryption "$k3s" secrets-encrypt status
run cilium-status "$k3s" kubectl exec -n kube-system ds/cilium -c cilium-agent \
  --request-timeout=10s -- cilium-dbg status
run hubble-observe "$k3s" kubectl exec -n kube-system ds/cilium -c cilium-agent \
  --request-timeout=10s -- hubble observe --last 20
run listeners "$ss" -tlnp
# is-enabled exits non-zero for a masked unit, which is the evidence sought.
run ssh-units "$systemctl" is-enabled ssh.service ssh.socket
run metadata-guard "$nft" list table inet mitstack_metadata_guard
run os-patch-units "$systemctl" is-enabled unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer

mkdir -p "$state_dir"
if [ -z "$(find "$state_dir/patch-check.json" -mmin -60 2> /dev/null)" ]; then
  printf '%s\n' "$patch_check" > "$state_dir/patch-check.sh"
  sh "$state_dir/patch-check.sh" > /dev/null 2>&1 || :
fi
[ ! -x "$dedicated_probe" ] || "$dedicated_probe" > /dev/null 2>&1 || :
# The scan runs detached, since it takes minutes, and systemd refuses a second
# mitstack-scan unit while one runs.
printf '%s\n' "$scan" > "$state_dir/scan.py"
run scan "$systemd_run" --no-block --collect --unit=mitstack-scan -p RuntimeMaxSec=3h \
  python3 -I "$state_dir/scan.py"

if [ ! -e "$reuse_file" ] &&
  curl -fs --connect-timeout 2 --max-time 5 -o "$work_dir/user-data" "$userdata_url"; then
  token=$(sed -n 's/^[[:space:]]*MITSTACK_ENROLMENT_TOKEN=//p' "$work_dir/user-data" | head -n 1)
  subscription_id=$(sed -n 's/^[[:space:]]*MITSTACK_SUBSCRIPTION_ID=//p' "$work_dir/user-data" | head -n 1)
  rm -f "$work_dir/user-data"
  if [ -n "$token" ] && [ -n "$subscription_id" ]; then
    # printf is a builtin, so the token is on no command line.
    printf 'Authorization: Bearer %s\n' "$token" > "$work_dir/probe-headers"
    printf '{"subscriptionId":"%s"}' "$subscription_id" > "$work_dir/probe-body"
    status=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 \
      -X POST -H @"$work_dir/probe-headers" -H 'Content-Type: application/json' \
      --data-binary @"$work_dir/probe-body" -o /dev/null -w '%{http_code}' \
      "$enrolment_url") || status=000
    rm -f "$work_dir/probe-headers" "$work_dir/probe-body"
    case $status in
      429) ;;
      2[0-9][0-9] | 4[0-9][0-9])
        printf '{"status":%d,"checkedAt":"%s"}\n' "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$reuse_file.partial"
        mv -f "$reuse_file.partial" "$reuse_file"
        ;;
    esac
  fi
fi

cp /proc/sys/kernel/random/boot_id "$work_dir/boot_id"
[ ! -e "$os_release" ] || cp "$os_release" "$work_dir/os-release"
[ ! -e "$cloud_init_log" ] || tail -n 300 "$cloud_init_log" > "$work_dir/cloud-init-output.log"
[ ! -e "$uu_log" ] || tail -n 1000 "$uu_log" > "$work_dir/unattended-upgrades.log"
[ ! -e "$reboot_required" ] || cp -p "$reboot_required" "$work_dir/reboot-required"
[ ! -e "$reboot_required.pkgs" ] || cp "$reboot_required.pkgs" "$work_dir/reboot-required.pkgs"
[ ! -e "$reuse_file" ] || cp "$reuse_file" "$work_dir/enrolment-reuse.json"
for f in patch-check.json scan-run.json kube-bench.json kubescape.json dedicated-server.json; do
  [ ! -e "$state_dir/$f" ] || cp "$state_dir/$f" "$work_dir/state/$f"
done

# Only each Secret's name, labels, project and url leave the host, and each
# admission fixture is applied as a server dry run, which persists nothing.
python3 - "$work_dir" "$json_file" "$k3s" <<'PY'
import json
import re
import subprocess
import sys

work, json_path, k3s = sys.argv[1:4]


def load(path):
    with open(path, "rb") as f:
        return json.loads(f.read())


def write(name, value):
    with open(work + "/" + name, "w") as f:
        json.dump(value, f)


# clip is the start of data within limit bytes of JSON text.
def clip(data, limit):
    kept, used = [], 0
    for ch in data[:limit].decode("utf-8", "ignore").replace("\0", ""):
        used += len(json.dumps(ch)) - 2
        if used > limit:
            break
        kept.append(ch)
    return "".join(kept)


def dry_run(namespace, rule, fixture):
    run = subprocess.run([k3s, "kubectl", "apply", "--dry-run=server", "-n", namespace, "-f", "-",
                          "--request-timeout=10s"], input=fixture.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {"rule": rule, "fixture": clip(fixture.encode(), 4096), "exitStatus": run.returncode, "message": clip(run.stdout, 2048)}


try:
    secrets = [{"metadata": {"name": s["metadata"]["name"], "labels": s["metadata"].get("labels") or {}},
                "data": {k: v for k, v in (s.get("data") or {}).items() if k in ("project", "url")}}
               for s in load(work + "/secrets.out")["items"]]
    write("secrets.out", {"items": secrets})
except (OSError, ValueError, KeyError, TypeError, AttributeError):
    open(work + "/secrets.out", "w").close()

def fixtures(namespace, name):
    data = load(work + "/" + name + ".out").get("data") or {}
    return [(namespace, rule, data[rule]) for rule in sorted(r for r in data if re.fullmatch("[a-z0-9-]+", r))]


# mitstack-node holds fixtures only on a seeded cluster, and no fixture past the report's admission budget is applied.
try:
    probe = fixtures("mitstack-admission-probe", "admission-fixtures")
    try:
        node = fixtures("mitstack-node", "node-admission-fixtures")
    except (OSError, ValueError, AttributeError):
        node = []
    runs, budget = [], 38400
    for namespace, rule, fixture in probe + node:
        entry = dry_run(namespace, rule, fixture)
        budget -= len(json.dumps(entry)) + 2
        if budget < 0:
            break
        runs.append(entry)
    write("admission.json", runs)
except (OSError, ValueError, AttributeError):
    pass

try:
    enrolment = load(json_path)
except (OSError, ValueError):
    enrolment = {}
write("enrolment-keys.json", list(enrolment) if isinstance(enrolment, dict) else [])
PY

tar -C "$work_dir" -cf - .
