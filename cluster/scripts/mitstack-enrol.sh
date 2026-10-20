#!/bin/sh
# Enrols this cluster with the mitstack platform and writes the repository,
# notifications and report-token Secrets k3s applies at its first start.
# Usage: mitstack-enrol, run once by mitstack-enrol.service before k3s starts.
# It exists to trade the user data's one-time enrolment token for the node's
# platform credentials, which the user data never carries.
set -eu

enrolment_url=${MITSTACK_ENROLMENT_URL:-https://api.mitstack.dev/v1/cluster-enrolments}
enrolment_dir=${MITSTACK_ENROLMENT_DIR:-/etc/mitstack}
manifests_dir=${MITSTACK_K3S_MANIFESTS_DIR:-/var/lib/rancher/k3s/server/manifests}
env_file=$enrolment_dir/enrolment.env
json_file=$enrolment_dir/enrolment.json
partial=$enrolment_dir/.enrolment.json.partial
# k3s skips a dot-prefixed name, so it never applies a partial.
credential=$manifests_dir/05-cluster-repository.yaml
credential_partial=$manifests_dir/.05-cluster-repository.yaml.partial
notifications=$manifests_dir/05-argocd-notifications-secret.yaml
notifications_partial=$manifests_dir/.05-argocd-notifications-secret.yaml.partial
# k3s applies the files in name order, so the namespace exists before the report token's Secret.
node_namespace=$manifests_dir/04-mitstack-node.yaml
report_token=$manifests_dir/05-report-token.yaml
report_token_partial=$manifests_dir/.05-report-token.yaml.partial
# A 429, a 5xx or a connection failure is retried for 31 seconds of sleep and about 91 seconds at most.
max_attempts=6

fail() {
  printf '%s\n' "mitstack-enrol: $*" >&2
  exit 1
}

# enrolment.env is read, never run.
env_value() {
  sed -n "s/^$1=//p" "$env_file" | head -n 1
}

[ -r "$env_file" ] || fail "cannot read $env_file"
token=$(env_value MITSTACK_ENROLMENT_TOKEN)
subscription_id=$(env_value MITSTACK_SUBSCRIPTION_ID)
repository_url=$(env_value MITSTACK_REPOSITORY_URL)
[ -n "$token" ] || fail "$env_file sets no MITSTACK_ENROLMENT_TOKEN"
[ -n "$subscription_id" ] || fail "$env_file sets no MITSTACK_SUBSCRIPTION_ID"
[ -n "$repository_url" ] || fail "$env_file sets no MITSTACK_REPOSITORY_URL"

umask 077
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"; rm -f "$partial" "$credential_partial" "$notifications_partial" "$report_token_partial"' EXIT
trap 'exit 1' HUP INT TERM

# printf is a builtin, so the token is on no command line.
printf 'Authorization: Bearer %s\n' "$token" > "$work_dir/headers"
printf '{"subscriptionId":"%s"}' "$subscription_id" > "$work_dir/body"

write_secrets() {
  python3 - "$partial" "$repository_url" "$credential_partial" "$notifications_partial" "$report_token_partial" "$node_namespace" <<'PY'
import json
import os
import sys

answer_path, repository_url, credential_path, notifications_path, report_token_path, namespace_path = sys.argv[1:7]
try:
    with open(answer_path, "rb") as f:
        answer = json.loads(f.read())
except (OSError, ValueError):
    sys.exit("mitstack-enrol: the platform answered 200 with a body that is not JSON")
if not isinstance(answer, dict):
    sys.exit("mitstack-enrol: the platform answered 200 with a body that is not a JSON object")
for field in ("repositoryToken", "repositoryTokenExpiresAt", "reportToken", "notificationToken"):
    value = answer.get(field)
    if not isinstance(value, str) or not value:
        sys.exit("mitstack-enrol: the platform answered 200 without a " + field)

for path, metadata, data in (
    (credential_path,
     {"name": "cluster-repository", "namespace": "argocd", "labels": {"argocd.argoproj.io/secret-type": "repository"}},
     {"type": "git", "url": repository_url, "username": "x-access-token", "password": answer["repositoryToken"]}),
    (notifications_path,
     {"name": "argocd-notifications-secret", "namespace": "argocd"},
     {"platform-token": answer["notificationToken"]}),
    (report_token_path,
     {"name": "mitstack-report-token", "namespace": "mitstack-node"},
     {"token": answer["reportToken"]}),
):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"apiVersion": "v1", "kind": "Secret", "metadata": metadata, "stringData": data}, f, indent=2)
        f.write("\n")
fd = os.open(namespace_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"apiVersion": "v1", "kind": "Namespace", "metadata": {
        "name": "mitstack-node", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}}, f, indent=2)
    f.write("\n")
PY
}

@REFUSAL_REASON@

attempt=1
delay=1
while :; do
  # The platform answers 424 when GitHub refuses the token for good, so only a
  # 429, a 5xx or no answer is retried.
  status=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 \
    -X POST -H @"$work_dir/headers" -H 'Content-Type: application/json' \
    --data-binary @"$work_dir/body" -o "$partial" -w '%{http_code}' \
    "$enrolment_url") || status=000
  case $status in
    200)
      mkdir -p "$manifests_dir"
      write_secrets || exit 1
      chmod 0600 "$credential_partial" "$notifications_partial" "$report_token_partial"
      mv -f "$credential_partial" "$credential"
      mv -f "$notifications_partial" "$notifications"
      mv -f "$report_token_partial" "$report_token"
      chmod 0600 "$partial"
      mv -f "$partial" "$json_file"
      exit 0
      ;;
    429 | 5[0-9][0-9] | 000) ;;
    *) fail "the platform refused the enrolment with HTTP $status$(refusal_reason "$partial")" ;;
  esac
  [ "$attempt" -lt "$max_attempts" ] ||
    fail "the platform did not enrol the cluster in $attempt attempts, the last answering HTTP $status"
  sleep "$delay"
  attempt=$((attempt + 1))
  delay=$((delay * 2))
done
