#!/bin/sh
# Names this k3s node by its Hetzner server id and binds k3s to its private IP,
# both read from the metadata service, unless an install already wrote them.
# Usage: mitstack-hcloud-node, run by cloud-init before k3s is installed.
# It exists because both values are known only once Hetzner has created the
# server, after its user data is rendered.
set -eu

metadata_url=${MITSTACK_METADATA_URL:-http://169.254.169.254/hetzner/v1/metadata}
dropin_dir=${MITSTACK_K3S_DROPIN_DIR:-/etc/rancher/k3s/config.yaml.d}
dropin=$dropin_dir/10-hcloud-node.yaml

fail() {
  echo "mitstack-hcloud-node: $*" >&2
  exit 1
}

# A dedicated server has no metadata service, so its install writes the
# drop-in, and this script then leaves it as it is.
[ -s "$dropin" ] && exit

# fetch retries for about a minute, since the metadata service may not answer
# yet at boot, and fails the script after that.
fetch() {
  attempt=1
  while :; do
    if body=$(curl -fsS --connect-timeout 2 --max-time 5 "$metadata_url/$1"); then
      printf '%s\n' "$body"
      return 0
    fi
    [ "$attempt" -lt 30 ] || fail "the metadata service never answered $1"
    sleep 2
    attempt=$((attempt + 1))
  done
}

server_id=$(fetch instance-id)
server_id=$(printf '%s' "$server_id" | tr -d '[:space:]')
case $server_id in
  '' | *[!0-9]*) fail "instance-id '$server_id' is not a numeric server id" ;;
esac

networks=$(fetch private-networks)
private_ip=$(printf '%s\n' "$networks" |
  sed -n 's/^[[:space:]-]*ip:[[:space:]]*\([0-9][0-9.]*\)[[:space:]]*$/\1/p' | head -n 1)
[ -n "$private_ip" ] || fail "the server has no IP on a private network"

mkdir -p "$dropin_dir"
cat > "$dropin.tmp" <<EOF
node-ip: "$private_ip"
advertise-address: "$private_ip"
bind-address: "$private_ip"
kubelet-arg+:
  - "provider-id=hcloud://$server_id"
EOF
chmod 0600 "$dropin.tmp"
mv "$dropin.tmp" "$dropin"
