#!/bin/sh
# Installs k3s from install.sh at a pinned k3s-io/k3s commit and the amd64
# release binary, each checked against its pinned SHA-256.
# Usage: mitstack-install-k3s, run by cloud-init once the node is enrolled.
# It exists so a node runs only the reviewed k3s bytes, never whatever
# install.sh would fetch.
set -eu

fail() {
  echo "mitstack-install-k3s: $*" >&2
  exit 1
}

download() {
  attempt=1
  while :; do
    if curl -fsS --proto '=https' --proto-redir '=https' --tlsv1.2 --location \
      --connect-timeout 20 --max-time 900 --output "$1" "$2"; then
      return 0
    fi
    if [ "$attempt" -ge 5 ]; then
      return 1
    fi
    sleep "$attempt"
    attempt=$((attempt + 1))
  done
}

verify() {
  actual=$(sha256sum "$1" | awk '{print $1}')
  [ "$actual" = "$2" ] || fail "$3 SHA-256 mismatch: expected $2, got $actual"
  echo "mitstack-install-k3s: $3 matches SHA-256 $2"
}

case $(uname -m) in
  x86_64 | amd64) ;;
  *) fail "the pinned k3s binary is amd64, and this machine is $(uname -m)" ;;
esac

umask 077
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

download "$work_dir/install.sh" 'https://raw.githubusercontent.com/k3s-io/k3s/{{.K3sInstallerCommit}}/install.sh' ||
  fail "could not download the k3s installer"
verify "$work_dir/install.sh" '{{.K3sInstallerSHA256}}' "the k3s installer"
download "$work_dir/k3s" 'https://github.com/k3s-io/k3s/releases/download/{{.K3sVersionPath}}/k3s' ||
  fail "could not download the k3s binary"
verify "$work_dir/k3s" '{{.K3sSHA256}}' "the k3s binary {{.K3sVersion}}"
install -o root -g root -m 0755 "$work_dir/k3s" /usr/local/bin/k3s

# Inherited installer controls must not point install.sh at other bytes.
unset INSTALL_K3S_ARTIFACT_URL INSTALL_K3S_CHANNEL INSTALL_K3S_CHANNEL_URL INSTALL_K3S_COMMIT INSTALL_K3S_PR
INSTALL_K3S_BIN_DIR=/usr/local/bin
INSTALL_K3S_SKIP_DOWNLOAD=true
INSTALL_K3S_SKIP_START=true
INSTALL_K3S_VERSION='{{.K3sVersion}}'
INSTALL_K3S_EXEC=server
export INSTALL_K3S_BIN_DIR INSTALL_K3S_SKIP_DOWNLOAD INSTALL_K3S_SKIP_START INSTALL_K3S_VERSION INSTALL_K3S_EXEC
sh "$work_dir/install.sh"
