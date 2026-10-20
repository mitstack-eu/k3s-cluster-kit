#!/bin/sh
# Runs collect.sh in the host's namespaces and leaves its archive as host.tar
# for mitstack-report.
# Usage: mitstack-host, run every five minutes by the privileged host container
# of mitstack-node-agent, whose pod shares the host's process namespace.
# It exists because the node report's host reads need the host itself.
set -eu

dir=$(dirname "$0")
host_dir=${MITSTACK_HOST_DIR:-/run/mitstack-host}

nsenter -t 1 -m -u -i -n -p -- /bin/sh -c "$(cat "$dir/collect.sh")" collect \
  "$(cat "$dir/mitstack-patch-check.sh")" "$(cat "$dir/mitstack-scan.py")" \
  < /dev/null > "$host_dir/host.tar.partial"
mv -f "$host_dir/host.tar.partial" "$host_dir/host.tar"
