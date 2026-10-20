#!/usr/bin/env bash
# Boots k3s with the boot components and the OpenBao manifests a cluster that
# hosts the platform carries in its user data, and proves OpenBao serves TLS
# alone from a certificate the cluster's authority signs and renews, that the
# init Job leaves OpenBao initialised and unsealed with its root token and
# recovery key in the repository only as PGP messages, that a key sealed by
# kubeseal against the controller's certificate reaches OpenBao through the
# writer, and that each slice namespace's service account reads its own sealed
# values and no other's, through External Secrets over TLS.
# Usage: sudo scripts/ci/openbao-boot-proof.sh, from the cluster directory, on a
#   disposable VM, since it installs k3s and runs a fake GitHub on the host.
# It exists because only a running OpenBao, Sealed Secrets controller and
# kubelet show what the boot manifests do, while the tests prove their bytes.
set -euo pipefail

golden=testdata/golden/userdata-hosts-platform.yaml
fixtures=testdata/boot
k3s_version=v1.36.3+k3s1
k3s_sha256=2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5
kubeseal_url=https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.40.0/kubeseal-0.40.0-linux-amd64.tar.gz
kubeseal_sha256=9314c35916646e9d59c8f06b1314574b4e79c4d76f079433607ed7b697bb5eb7
manifests=/var/lib/rancher/k3s/server/manifests
image=mitstack-node-agent:proof
github_port=8999
boot_files=(01-openbao-seal-key.yaml 01-sealed-secrets-key.yaml 02-boot-components.yaml 02-openbao-tls.yaml 04-openbao-boot.yaml)
# The serving certificate lives an hour here and renews two minutes after each
# issue, so the proof sees a renewal in minutes rather than the 60 days a node waits.
proof_lifetime=1h
proof_renew_before=58m

work=$(mktemp -d)
export GNUPGHOME=$work/gnupg KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl() { k3s kubectl "$@"; }

fail() {
  printf 'openbao-boot-proof: FAIL: %s\n' "$*" >&2
  exit 1
}

diagnose() {
  set +e
  echo "::group::diagnostics"
  kubectl get pods,jobs,sealedsecrets,secrets,certificates,externalsecrets -A -o wide
  kubectl -n mitstack-node logs job/openbao-init --all-containers --tail=200
  kubectl -n mitstack-node logs deployment/github-app-writer --tail=200
  kubectl -n mitstack-node logs deployment/app-secrets-writer --tail=200
  kubectl -n kube-system logs deployment/sealed-secrets-controller --tail=100
  kubectl -n openbao logs openbao-0 --all-containers --tail=100
  kubectl -n cert-manager logs deployment/cert-manager --tail=100
  kubectl -n cert-manager logs deployment/trust-manager --tail=100
  kubectl -n external-secrets logs deployment/external-secrets --tail=100
  kubectl get events -A --sort-by=.lastTimestamp | tail -n 60
  cat "$work/github.log"
  tail -n 100 /var/log/mitstack-k3s.log
  echo "::endgroup::"
}

[ "$(id -u)" -eq 0 ] || fail "run as root, since it installs k3s"
[ -f "$golden" ] || fail "$golden does not exist, so there are no recorded boot manifests to run"
on_exit() {
  local status=$?
  [ "$status" -eq 0 ] || diagnose
  [ -z "${github_pid:-}" ] || kill "$github_pid" 2>/dev/null || true
}
trap on_exit EXIT

echo "::group::the node agent's image, built from this commit"
docker build -q -f scripts/nodeagent/Dockerfile -t "$image" .
install -d /var/lib/rancher/k3s/agent/images
docker save "$image" -o /var/lib/rancher/k3s/agent/images/mitstack-node-agent.tar
echo "::endgroup::"

echo "::group::a fake GitHub on the host, for the init Job's commit"
host_ip=$(hostname -I | awk '{print $1}')
python3 -I - "$github_port" "$work/repo" >"$work/github.log" 2>&1 <<'PY' &
import base64, http.server, json, os, sys

port, repo = int(sys.argv[1]), sys.argv[2]
os.makedirs(repo, exist_ok=True)

class Fake(http.server.BaseHTTPRequestHandler):
    def answer(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def file(self):
        name = self.path.rsplit("/contents/", 1)[-1]
        return os.path.join(repo, name) if "/contents/" in self.path and "/" not in name else None

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ok = self.path.endswith("/access_tokens") and self.headers.get("Authorization", "").count(".") == 2
        self.answer(201 if ok else 401, {"token": "ghs_proof"} if ok else {})

    def do_GET(self):
        path = self.file()
        if path and os.path.exists(path):
            self.answer(200, {"content": base64.b64encode(open(path, "rb").read()).decode()})
        else:
            self.answer(404, {})

    def do_PUT(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        path = self.file()
        if not path or os.path.exists(path):
            return self.answer(422, {})
        open(path, "wb").write(base64.b64decode(body["content"]))
        self.answer(201, {})

http.server.ThreadingHTTPServer(("0.0.0.0", port), Fake).serve_forever()
PY
github_pid=$!
echo "fake GitHub at http://${host_ip}:${github_port}"
echo "::endgroup::"

echo "::group::the boot manifests from ${golden}"
install -d -m 0700 /var/lib/openbao
install -d -m 0700 "$manifests"
python3 -I - "$golden" "$manifests" "$image" "http://${host_ip}:${github_port}" "$proof_lifetime" "$proof_renew_before" "${boot_files[@]}" <<'PY'
import base64, gzip, sys, yaml

golden, out, image, github, lifetime, renew_before, names = *sys.argv[1:7], sys.argv[7:]
files = {f["path"].rsplit("/", 1)[-1]: f for f in yaml.safe_load(open(golden).read().split("\n", 1)[1])["write_files"]}
for name in names:
    f = files[name]
    content = gzip.decompress(base64.b64decode(f["content"])).decode() if f.get("encoding") == "gz+b64" else f["content"]
    if name == "04-openbao-boot.yaml":
        docs = list(yaml.safe_load_all(content))
        for doc in docs:
            for ctr in (doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers") or []):
                ctr["image"] = image
                if doc["kind"] == "Job":
                    ctr["env"].append({"name": "MITSTACK_GITHUB_API_URL", "value": github})
        content = yaml.safe_dump_all(docs)
    if name == "02-openbao-tls.yaml":
        docs = list(yaml.safe_load_all(content))
        for doc in docs:
            if doc["kind"] == "Certificate" and doc["metadata"]["name"] == "openbao-tls":
                doc["spec"].update(duration=lifetime, renewBefore=renew_before)
        content = yaml.safe_dump_all(docs)
    with open(out + "/" + name, "w") as w:
        w.write(content)
    print("wrote", name)
PY
echo "::endgroup::"

echo "::group::k3s ${k3s_version}, which applies the boot manifests"
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
echo "::endgroup::"

echo "::group::the init Job"
for _ in $(seq 1 120); do
  kubectl -n mitstack-node get job openbao-init >/dev/null 2>&1 && break
  sleep 5
done
kubectl -n mitstack-node wait --for=condition=Complete job/openbao-init --timeout=900s
kubectl -n mitstack-node logs job/openbao-init
echo "::endgroup::"

# served_serial prints the serial of the certificate OpenBao serves, once it verifies against the cluster's authority.
served_serial() {
  openssl s_client -connect "${openbao_ip}:8200" -servername openbao.openbao.svc -CAfile "$work/ca.crt" \
    -verify_return_error </dev/null 2>/dev/null | openssl x509 -noout -serial
}

echo "::group::OpenBao serves TLS alone, from a certificate the cluster's authority signs"
kubectl -n mitstack-node get configmap openbao-ca -o jsonpath='{.data.ca\.crt}' >"$work/ca.crt"
openssl x509 -in "$work/ca.crt" -noout -subject
openbao_ip=$(kubectl -n openbao get service openbao -o jsonpath='{.spec.clusterIP}')
health=$(curl -fsS --cacert "$work/ca.crt" --resolve "openbao.openbao.svc:8200:${openbao_ip}" https://openbao.openbao.svc:8200/v1/sys/health) ||
  fail "a request to https://openbao.openbao.svc:8200 that verifies the cluster's authority failed"
echo "$health"
grep -q '"initialized":true' <<<"$health" || fail "OpenBao's health over TLS reads ${health}, want initialized"
plain=$(curl -sS "http://${openbao_ip}:8200/v1/sys/health" 2>&1 || true)
echo "plain http answer: ${plain}"
grep -q '"initialized"' <<<"$plain" && fail "a plain http request to port 8200 got OpenBao's answer: ${plain}"
first_serial=$(served_serial) || fail "OpenBao's certificate does not verify against the authority in openbao-ca"
echo "openbao-boot-proof: PASS: OpenBao answers over TLS with a certificate the cluster's authority signed, ${first_serial}, and a plain http request gets no OpenBao answer"
echo "::endgroup::"

echo "::group::bao status"
status=$(kubectl -n openbao exec openbao-0 -c openbao -- bao status || true)
echo "$status"
grep -Eq '^Initialized[[:space:]]+true$' <<<"$status" || fail "bao status does not read Initialized true"
grep -Eq '^Sealed[[:space:]]+false$' <<<"$status" || fail "bao status does not read Sealed false"
echo "openbao-boot-proof: PASS: bao status reads Initialized true and Sealed false"
echo "::endgroup::"

echo "::group::openbao-init.asc"
[ -f "$work/repo/openbao-init.asc" ] || fail "the init Job committed no openbao-init.asc"
cat "$work/repo/openbao-init.asc"
install -d -m 0700 "$GNUPGHOME"
gpg --batch --quiet --import "$fixtures/owner-secret.asc"
python3 -I - "$work/repo/openbao-init.asc" "$work" <<'PY'
import sys

text, work = open(sys.argv[1]).read(), sys.argv[2]
blocks = [b + "-----END PGP MESSAGE-----\n" for b in text.split("-----END PGP MESSAGE-----\n")[:-1]]
if len(blocks) != 2 or not all("-----BEGIN PGP MESSAGE-----" in b for b in blocks):
    sys.exit("openbao-init.asc holds %d PGP messages, want two" % len(blocks))
for name, block in zip(("root-token.asc", "recovery-key.asc"), blocks):
    open(work + "/" + name, "w").write(block[block.index("-----BEGIN"):])
PY
root_token=$(gpg --batch --quiet --decrypt "$work/root-token.asc")
recovery_key=$(gpg --batch --quiet --decrypt "$work/recovery-key.asc")
if [ -z "$root_token" ] || [ -z "$recovery_key" ]; then
  fail "a message in openbao-init.asc decrypts to nothing"
fi
grep -qF "$root_token" "$work/repo/openbao-init.asc" && fail "openbao-init.asc holds the root token in plain text"
kubectl -n mitstack-node logs job/openbao-init | grep -qF "$root_token" && fail "the init Job logged the root token"
echo "openbao-boot-proof: PASS: openbao-init.asc holds the root token and the recovery key only as PGP messages that decrypt with the test owner's key"
echo "::endgroup::"

# kv_sha256 prints the sha256 of the App's key in OpenBao, or nothing while the writer has not written it.
kv_sha256() {
  local key
  # shellcheck disable=SC2016 # the pod's shell reads the token from stdin, so it never reaches an argument list.
  key=$(printf '%s' "$root_token" | kubectl -n openbao exec -i openbao-0 -c openbao -- sh -c \
    'BAO_TOKEN=$(cat) bao kv get -mount=kv -field=private-key argocd/github-app' 2>/dev/null) || return 0
  printf '%s\n' "$key" | sha256sum | cut -d' ' -f1
}

await_kv() {
  local want=$1 got=
  for _ in $(seq 1 60); do
    got=$(kv_sha256)
    [ "$got" = "$want" ] && return 0
    sleep 5
  done
  fail "kv argocd/github-app private-key has sha256 ${got}, want ${want}"
}

echo "::group::the boot's sealed App key in OpenBao"
await_kv "$(sha256sum <"$fixtures/github-app.pem" | cut -d' ' -f1)"
echo "openbao-boot-proof: PASS: the App key sealed in the user data reached kv argocd/github-app"
echo "::endgroup::"

echo "::group::a key sealed by kubeseal against the controller's certificate"
curl -fsSL --proto '=https' -o "$work/kubeseal.tar.gz" "$kubeseal_url"
echo "${kubeseal_sha256}  $work/kubeseal.tar.gz" | sha256sum -c -
tar -xzf "$work/kubeseal.tar.gz" -C "$work" kubeseal
"$work/kubeseal" --controller-namespace kube-system --controller-name sealed-secrets-controller --fetch-cert >"$work/published.crt"
cmp -s "$work/published.crt" "$fixtures/sealed-secrets.crt" || fail "the controller publishes another certificate than the block wrote"
openssl genrsa -traditional -out "$work/rotated.pem" 2048 2>/dev/null
kubectl -n mitstack-node create secret generic github-app-key --from-file=private-key="$work/rotated.pem" --dry-run=client -o yaml |
  "$work/kubeseal" --cert "$work/published.crt" -o yaml | kubectl apply -f -
want=$(sha256sum <"$work/rotated.pem" | cut -d' ' -f1)
await_kv "$want"
echo "kv argocd/github-app private-key sha256: ${want}"
echo "openbao-boot-proof: PASS: a .pem sealed by kubeseal against the controller's certificate reached kv argocd/github-app"
echo "::endgroup::"

# root_greeting prints GREETING at kv apps/<namespace>/env as the root token reads it, or nothing before it is written.
root_greeting() {
  # shellcheck disable=SC2016 # the pod's shell reads the token from stdin, so it never reaches an argument list.
  printf '%s' "$root_token" | kubectl -n openbao exec -i openbao-0 -c openbao -- sh -c \
    'BAO_TOKEN=$(cat) bao kv get -mount=kv -field=GREETING "apps/$1/env"' sh "$1" 2>/dev/null || true
}

await_greeting() {
  local namespace=$1 want=$2 got=
  for _ in $(seq 1 60); do
    got=$(root_greeting "$namespace")
    [ "$got" = "$want" ] && return 0
    sleep 5
  done
  fail "kv apps/${namespace}/env GREETING reads '${got}', want '${want}'"
}

# slice_login prints the OpenBao token the namespace's service account app gets from the role app-secrets.
slice_login() {
  kubectl -n "$1" create token app --duration=10m |
    kubectl -n openbao exec -i openbao-0 -c openbao -- bao write -field=token auth/kubernetes/login role=app-secrets jwt=-
}

# slice_read reads kv/data/apps/<namespace>/env with a slice's token, printing its data as JSON or OpenBao's refusal.
slice_read() {
  # shellcheck disable=SC2016 # the pod's shell reads the token from stdin, so it never reaches an argument list.
  printf '%s' "$1" | kubectl -n openbao exec -i openbao-0 -c openbao -- sh -c \
    'BAO_TOKEN=$(cat) bao read -format=json -field=data "kv/data/apps/$1/env"' sh "$2" 2>&1
}

echo "::group::each slice namespace reads its own apps path and is refused another's"
want_a="app-a $(openssl rand -hex 8)"
want_b="app-b $(openssl rand -hex 8)"
for namespace in app-a app-b; do
  kubectl create namespace "$namespace"
  kubectl -n "$namespace" create serviceaccount app
done
kubectl -n mitstack-node create secret generic app-secrets \
  --from-literal=app-a.GREETING="$want_a" --from-literal=app-b.GREETING="$want_b" --dry-run=client -o yaml |
  "$work/kubeseal" --cert "$work/published.crt" -o yaml | kubectl apply -f -
await_greeting app-a "$want_a"
await_greeting app-b "$want_b"
echo "openbao-boot-proof: PASS: the writer wrote the sealed app-secrets to kv apps/app-a/env and kv apps/app-b/env"
token_a=$(slice_login app-a) || fail "app-a's service account app could not log in with the role app-secrets"
read_a=$(slice_read "$token_a" app-a) || fail "app-a's service account could not read apps/app-a/env: ${read_a}"
got_a=$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)["GREETING"])' <<<"$read_a")
[ "$got_a" = "$want_a" ] || fail "app-a's service account read GREETING '${got_a}' at apps/app-a/env, want '${want_a}'"
echo "openbao-boot-proof: PASS: app-a's service account logged in with the role app-secrets and read the sealed value the writer wrote to apps/app-a/env"
if refused=$(slice_read "$token_a" app-b); then
  fail "app-a's service account read apps/app-b/env: ${refused}"
fi
grep -q "permission denied" <<<"$refused" || fail "app-a's read of apps/app-b/env failed with '${refused}', want permission denied"
echo "openbao-boot-proof: PASS: app-a's service account was refused apps/app-b/env with permission denied"
echo "::endgroup::"

echo "::group::an ExternalSecret in a slice reads its value from OpenBao over TLS"
kubectl apply -f - <<YAML
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: openbao
  namespace: app-a
spec:
  provider:
    vault:
      server: https://openbao.openbao.svc:8200
      caProvider:
        type: ConfigMap
        name: openbao-ca
        key: ca.crt
      path: kv
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: app-secrets
          serviceAccountRef:
            name: app
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: greeting
  namespace: app-a
spec:
  refreshInterval: 1m
  secretStoreRef:
    kind: SecretStore
    name: openbao
  target:
    name: greeting
  data:
    - secretKey: GREETING
      remoteRef:
        key: apps/app-a/env
        property: GREETING
YAML
kubectl -n app-a wait --for=condition=Ready externalsecret/greeting --timeout=300s
got=$(kubectl -n app-a get secret greeting -o jsonpath='{.data.GREETING}' | base64 -d)
[ "$got" = "$want_a" ] || fail "the ExternalSecret wrote GREETING '${got}', want '${want_a}'"
echo "openbao-boot-proof: PASS: External Secrets in app-a verified OpenBao against openbao-ca and wrote the sealed value apps/app-a/env holds"
echo "::endgroup::"

echo "::group::the serving certificate renews with no hand act, and OpenBao serves the renewed one"
first_serial=$(served_serial) || fail "OpenBao's certificate does not verify against the authority in openbao-ca"
echo "$(date -u +%FT%TZ) OpenBao serves ${first_serial}"
second_serial=$first_serial
for _ in $(seq 1 60); do
  second_serial=$(served_serial || true)
  [ -n "$second_serial" ] && [ "$second_serial" != "$first_serial" ] && break
  sleep 10
done
if [ -z "$second_serial" ] || [ "$second_serial" = "$first_serial" ]; then
  fail "OpenBao still serves ${first_serial} ten minutes on, though its certificate renews every two minutes"
fi
echo "$(date -u +%FT%TZ) OpenBao serves ${second_serial}"
kubectl -n openbao logs openbao-0 -c tls-reload
status=$(kubectl -n openbao exec openbao-0 -c openbao -- bao status || true)
grep -Eq '^Sealed[[:space:]]+false$' <<<"$status" || fail "bao status does not read Sealed false after the renewal"
echo "openbao-boot-proof: PASS: OpenBao served ${first_serial} and then ${second_serial}, each verifying against the cluster's authority, and stayed unsealed"
echo "::endgroup::"
