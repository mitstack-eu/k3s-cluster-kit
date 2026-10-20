#!/bin/sh
# Trades the report token for fresh repository tokens and patches each into
# the password of the Secret Argo CD reads that repository with, one attempt
# per run.
# Usage: mitstack-repo-token, run every fifteen minutes by the
# mitstack-repo-token CronJob.
# It exists because a repository token lasts an hour, and Argo CD would lose a
# repository once its token expired.
set -eu

refresh_url=${MITSTACK_REFRESH_URL:-https://api.mitstack.dev/v1/cluster-repository-tokens}
token_file=${MITSTACK_TOKEN_FILE:-/var/run/mitstack/token}
# false leaves cluster-repository to External Secrets, as on mitstack's home
# cluster, whose Argo CD must not take its token from the platform it hosts.
patch_cluster_repository=${MITSTACK_PATCH_CLUSTER_REPOSITORY:-true}
kube_api=${MITSTACK_KUBE_API:-https://kubernetes.default.svc}
kube_ca_file=${MITSTACK_KUBE_CA_FILE:-/var/run/secrets/kubernetes.io/serviceaccount/ca.crt}
kube_token_file=${MITSTACK_KUBE_TOKEN_FILE:-/var/run/secrets/kubernetes.io/serviceaccount/token}

fail() {
  printf '%s\n' "mitstack-repo-token: $*" >&2
  exit 1
}

# shellcheck source=scripts/refusal-reason.sh
. "$(dirname "$0")/refusal-reason.sh"

[ -r "$token_file" ] || fail "cannot read the report token at $token_file"

umask 077
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM

# write_bearer_header writes the one-line token in the file $1 as an
# Authorization header into the file $2, so the token is on no command line,
# and without a usable token writes nothing and fails.
write_bearer_header() {
  python3 - "$1" "$2" "$3" <<'PY'
import os
import sys

token_path, headers_path, what = sys.argv[1:4]
try:
    with open(token_path, "rb") as f:
        token = f.read().decode("utf-8").rstrip("\n")
except (OSError, ValueError):
    sys.exit("mitstack-repo-token: cannot read " + what)
if not token or "\n" in token or "\r" in token:
    sys.exit("mitstack-repo-token: " + what + " is empty or not one line")
fd = os.open(headers_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("Authorization: Bearer " + token + "\n")
PY
}

write_bearer_header "$token_file" "$work_dir/headers" "the report token" || exit 1
write_bearer_header "$kube_token_file" "$work_dir/kube-headers" "the service-account token" || exit 1

# The platform ignores the body, so an empty object is sent.
status=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 \
  -X POST -H @"$work_dir/headers" -H 'Content-Type: application/json' \
  --data-binary '{}' -o "$work_dir/answer" -w '%{http_code}' \
  "$refresh_url") || status=000
case $status in
  200) ;;
  429 | 5[0-9][0-9] | 000) fail "the platform did not renew the repository token: HTTP $status" ;;
  *) fail "the platform refused the repository token with HTTP $status$(refusal_reason "$work_dir/answer")" ;;
esac

# python3 writes one patch per Secret, and nothing when any part of the answer is unusable.
python3 - "$work_dir" <<'PY' || exit 1
import json
import os
import re
import sys

work = sys.argv[1]
APP_PROJECT = re.compile(r"app-([a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)")


def refuse(reason):
    sys.exit("mitstack-repo-token: the platform answered 200 " + reason)


def app_repository(index, entry):
    entry = entry if isinstance(entry, dict) else {}
    project, url, token = entry.get("project"), entry.get("repoUrl"), entry.get("repositoryToken")
    app = APP_PROJECT.fullmatch(project) if isinstance(project, str) else None
    if not app or not isinstance(url, str) or not url.startswith("https://") or not isinstance(token, str) or not token:
        refuse("with an unusable appRepositories[%d]" % index)
    return "app-repository-" + app.group(1), token


try:
    with open(work + "/answer", "rb") as f:
        answer = json.loads(f.read())
except (OSError, ValueError):
    refuse("with a body that is not JSON")
token = answer.get("repositoryToken") if isinstance(answer, dict) else None
if not isinstance(token, str) or not token:
    refuse("without a repositoryToken")
entries = answer.get("appRepositories", [])
if not isinstance(entries, list):
    refuse("with an appRepositories that is not a list")
secrets = dict([("cluster-repository", token)] + [app_repository(i, e) for i, e in enumerate(entries)])
os.mkdir(work + "/patches")
for name, secret_token in secrets.items():
    fd = os.open(work + "/patches/" + name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"stringData": {"password": secret_token}}, f)
PY

# patch sends one Secret's patch file to the API server as a merge patch and
# sets patch_status. It sends no read first, since the refresh holds only
# patch on named Secrets.
patch() {
  patch_status=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 \
    --cacert "$kube_ca_file" -X PATCH -H @"$work_dir/kube-headers" \
    -H 'Content-Type: application/merge-patch+json' \
    --data-binary @"$work_dir/patches/$1" -o /dev/null -w '%{http_code}' \
    "$kube_api/api/v1/namespaces/argocd/secrets/$1") || patch_status=000
  [ "$patch_status" = 200 ]
}
if [ "$patch_cluster_repository" != false ]; then
  patch cluster-repository ||
    fail "could not patch the Secret cluster-repository in argocd: HTTP $patch_status"
fi
rm "$work_dir/patches/cluster-repository"
# A slice's Secret or Role that Argo CD has not synced yet is retried next run.
for path in "$work_dir"/patches/*; do
  [ -e "$path" ] || continue
  name=$(basename "$path")
  patch "$name" ||
    printf '%s\n' "mitstack-repo-token: could not patch $name in argocd: HTTP $patch_status; the next run tries again" >&2
done
