#!/usr/bin/env bash
# Boots k3s with the seeded node agent built from this commit, and proves the
# report container's kubectl reads the cluster with its service account,
# through the same flags the report passes, and that the refresh's merge
# patch of a repository Secret passes the refresh's patch-only role.
# Usage: sudo scripts/ci/node-agent-proof.sh, from the cluster directory, on a
#   disposable VM, since it installs k3s.
# It exists because kubectl falls back to localhost:8080 when an override flag
# meets no kubeconfig, and a patch-only role refuses a patch that reads its
# object first, which only a real API server and kubelet show.
set -euo pipefail

manifest=scripts/nodeagent/node-agent.yaml
k3s_version=v1.36.3+k3s1
k3s_sha256=2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5
image=mitstack-node-agent:proof
seeded=$(mktemp)

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl() { k3s kubectl "$@"; }

fail() {
  printf 'node-agent-proof: FAIL: %s\n' "$*" >&2
  exit 1
}

diagnose() {
  set +e
  echo "::group::diagnostics"
  kubectl get pods,jobs -A -o wide
  kubectl -n mitstack-node describe deployment/mitstack-node-agent
  kubectl get events -A --sort-by=.lastTimestamp | tail -n 60
  tail -n 100 /var/log/mitstack-k3s.log
  echo "::endgroup::"
}

[ "$(id -u)" -eq 0 ] || fail "run as root, since it installs k3s"
trap '[ $? -eq 0 ] || diagnose' EXIT

echo "::group::the node agent's image, built from this commit"
docker build -q -f scripts/nodeagent/Dockerfile -t "$image" .
install -d /var/lib/rancher/k3s/agent/images
docker save "$image" -o /var/lib/rancher/k3s/agent/images/mitstack-node-agent.tar
echo "::endgroup::"

echo "::group::k3s ${k3s_version}"
curl -fsSL --proto '=https' -o /usr/local/bin/k3s \
  "https://github.com/k3s-io/k3s/releases/download/${k3s_version/+/%2B}/k3s"
echo "${k3s_sha256}  /usr/local/bin/k3s" | sha256sum -c -
chmod 755 /usr/local/bin/k3s
k3s server --disable local-storage --disable traefik --write-kubeconfig-mode 600 \
  >/var/log/mitstack-k3s.log 2>&1 &
for _ in $(seq 1 90); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 2
done
kubectl wait --for=condition=Ready node --all --timeout=180s
# The agent's kubeconfig names kubernetes.default.svc, which resolves only once CoreDNS serves.
for _ in $(seq 1 90); do
  kubectl -n kube-system get deployment coredns >/dev/null 2>&1 && break
  sleep 2
done
kubectl -n kube-system rollout status deployment/coredns --timeout=180s
echo "::endgroup::"

# k3s runs flannel here rather than Cilium, so the egress policy has no CRD to
# land on, and the agent's namespaces outside mitstack-node do not exist yet.
echo "::group::the seeded node agent, its image swapped for this commit's"
kubectl create namespace argocd
kubectl create namespace system-upgrade
python3 -I - "$manifest" "$image" >"$seeded" <<'PY'
import sys, yaml

manifest, image = sys.argv[1], sys.argv[2]
docs = yaml.safe_load_all(open(manifest).read().replace("@NODE_AGENT_IMAGE@", image))
print(yaml.safe_dump_all([d for d in docs if d and d["kind"] != "CiliumNetworkPolicy"]))
PY
kubectl apply -f "$seeded"
kubectl -n mitstack-node create secret generic mitstack-report-token --from-literal=token=proof
kubectl -n mitstack-node rollout status deployment/mitstack-node-agent --timeout=180s
echo "::endgroup::"

echo "::group::the report container's service-account reads"
node=$(kubectl get nodes -o name)
got=$(kubectl -n mitstack-node exec deployment/mitstack-node-agent -c report -- \
  kubectl get nodes -o name --request-timeout=10s 2>&1) ||
  fail "the report container's kubectl get nodes --request-timeout=10s failed: ${got}"
[ "$got" = "$node" ] || fail "the report container's kubectl listed ${got}, want ${node}"
echo "node-agent-proof: PASS: the report container listed ${got} with its service account"
kubectl -n argocd run argocd-proof --image="$image" --restart=Never --command -- sleep 600
got=$(kubectl -n mitstack-node exec deployment/mitstack-node-agent -c report -- \
  kubectl get pods -n argocd -o name --request-timeout=10s 2>&1) ||
  fail "the report container's kubectl get pods -n argocd failed: ${got}"
[ "$got" = "pod/argocd-proof" ] || fail "the report container listed ${got} in argocd, want pod/argocd-proof"
echo "node-agent-proof: PASS: the report container listed the pods in argocd"
echo "::endgroup::"

# A self access review is open to every authenticated identity, so it shows
# which account the refresh container's kubectl reaches the API server as.
echo "::group::the refresh container's service account"
python3 -I - "$seeded" <<'PY' | kubectl apply -f -
import sys, yaml

cron = next(d for d in yaml.safe_load_all(open(sys.argv[1])) if d["kind"] == "CronJob")
job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "refresh-proof", "namespace": "mitstack-node"}, "spec": cron["spec"]["jobTemplate"]["spec"]}
job["spec"]["template"]["spec"]["containers"][0]["command"] = ["kubectl", "auth", "can-i", "patch", "secret/cluster-repository", "-n", "argocd", "--request-timeout=10s"]
print(yaml.safe_dump(job))
PY
kubectl -n mitstack-node wait --for=condition=Complete job/refresh-proof --timeout=180s ||
  fail "the refresh container's kubectl auth can-i failed: $(kubectl -n mitstack-node logs job/refresh-proof 2>&1)"
got=$(kubectl -n mitstack-node logs job/refresh-proof)
[ "$got" = yes ] || fail "the refresh container's kubectl auth can-i patch secret/cluster-repository printed ${got}, want yes"
echo "node-agent-proof: PASS: the refresh container reached the API server as mitstack-repo-token"
echo "::endgroup::"

# The Job sends the refresh's own request form, since the refresh itself needs
# the platform to hand it a token.
echo "::group::the refresh container's merge patch of cluster-repository"
kubectl -n argocd create secret generic cluster-repository --from-literal=password=before
python3 -I - "$seeded" <<'PY' | kubectl apply -f -
import sys, yaml

patch = r"""set -eu
umask 077
sa=/var/run/secrets/kubernetes.io/serviceaccount
{ printf 'Authorization: Bearer '; cat "$sa/token"; echo; } >/tmp/kube-headers
printf '%s' '{"stringData":{"password":"after"}}' >/tmp/patch
curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 --cacert "$sa/ca.crt" -X PATCH -H @/tmp/kube-headers -H 'Content-Type: application/merge-patch+json' --data-binary @/tmp/patch -o /dev/null -w '%{http_code}' https://kubernetes.default.svc/api/v1/namespaces/argocd/secrets/cluster-repository
"""
cron = next(d for d in yaml.safe_load_all(open(sys.argv[1])) if d["kind"] == "CronJob")
job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "patch-proof", "namespace": "mitstack-node"}, "spec": cron["spec"]["jobTemplate"]["spec"]}
job["spec"]["template"]["spec"]["containers"][0]["command"] = ["sh", "-c", patch]
print(yaml.safe_dump(job))
PY
kubectl -n mitstack-node wait --for=condition=Complete job/patch-proof --timeout=180s ||
  fail "the refresh container's PATCH of cluster-repository did not complete: $(kubectl -n mitstack-node logs job/patch-proof 2>&1)"
got=$(kubectl -n mitstack-node logs job/patch-proof)
[ "$got" = 200 ] || fail "the refresh container's PATCH of cluster-repository answered HTTP ${got}, want 200"
got=$(kubectl -n argocd get secret cluster-repository -o jsonpath='{.data.password}' | base64 -d)
[ "$got" = after ] || fail "cluster-repository holds the password ${got} after the PATCH, want after"
echo "node-agent-proof: PASS: the refresh container patched cluster-repository with its patch-only role"
echo "::endgroup::"
