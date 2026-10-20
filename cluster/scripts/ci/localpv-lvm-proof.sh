#!/usr/bin/env bash
# Runs k3s over a loop-backed volume group vg0, applies the LocalPV-LVM
# component a dedicated server's seed writes, and proves that a 1Gi claim binds
# a 1Gi logical volume while a claim larger than vg0's free space stays Pending
# with no logical volume made for it.
# Usage: sudo scripts/ci/localpv-lvm-proof.sh, from the cluster directory, on a
#   disposable VM, since it installs k3s and creates a volume group.
# It exists because only a running kernel, LVM and kubelet show what the
# seeded storage does, while the seed tests prove only its bytes.
set -euo pipefail

component=clusterbases/localpv-lvm
k3s_version=v1.36.3+k3s1
k3s_sha256=2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5
pause_image=registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a
vg_image=/var/tmp/mitstack-vg0.img
vg_size=4G
fits=1Gi
fits_bytes=1073741824
too_big=8Gi
pending_seconds=120

kubectl() { k3s kubectl "$@"; }

fail() {
  printf 'localpv-lvm-proof: FAIL: %s\n' "$*" >&2
  exit 1
}

diagnose() {
  set +e
  echo "::group::diagnostics"
  kubectl get nodes,storageclass,csidriver,csistoragecapacity -A -o wide
  kubectl get pods,pvc -A -o wide
  kubectl get lvmvolumes,lvmnodes -A -o yaml
  kubectl describe pvc -n default
  kubectl describe pod -n default
  kubectl -n kube-system logs daemonset/lvm-localpv-node --all-containers --tail=200
  kubectl -n kube-system logs deployment/lvm-localpv-controller --all-containers --tail=200
  vgs
  lvs -a
  tail -n 100 /var/log/mitstack-k3s.log
  echo "::endgroup::"
}

[ "$(id -u)" -eq 0 ] || fail "run as root, since it installs k3s and creates a volume group"
[ -d "$component" ] || fail "$component does not exist, so a dedicated server's seed carries no LocalPV-LVM component to apply"
on_exit() {
  local status=$?
  [ "$status" -eq 0 ] || diagnose
}
trap on_exit EXIT

echo "::group::volume group vg0 on a ${vg_size} loop device"
command -v lvs >/dev/null || { apt-get update -qq && apt-get install -y -qq lvm2; }
modprobe dm_mod
truncate -s "$vg_size" "$vg_image"
loop=$(losetup --find --show "$vg_image")
pvcreate -q "$loop"
vgcreate -q vg0 "$loop"
vgs vg0
echo "::endgroup::"

echo "::group::k3s ${k3s_version}, without its local-path provisioner"
curl -fsSL --proto '=https' -o /usr/local/bin/k3s \
  "https://github.com/k3s-io/k3s/releases/download/${k3s_version/+/%2B}/k3s"
echo "${k3s_sha256}  /usr/local/bin/k3s" | sha256sum -c -
chmod 755 /usr/local/bin/k3s
k3s server --disable local-storage --disable traefik --write-kubeconfig-mode 600 \
  >/var/log/mitstack-k3s.log 2>&1 &
# The API answers before the kubelet registers its node, and kubectl wait
# refuses a selector that matches nothing.
for _ in $(seq 1 90); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 2
done
kubectl wait --for=condition=Ready node --all --timeout=180s
echo "::endgroup::"

echo "::group::apply ${component}"
kubectl apply -n kube-system -f "$component"
kubectl -n kube-system rollout status daemonset/lvm-localpv-node --timeout=300s
kubectl -n kube-system rollout status deployment/lvm-localpv-controller --timeout=300s
kubectl get storageclass
default_class=$(kubectl get storageclass \
  -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}')
[ "$default_class" = openebs-lvm ] || fail "the default storage class is '${default_class}', want openebs-lvm alone"
echo "::endgroup::"

claim() {
  local name=$1 size=$2
  kubectl apply -n default -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${name}
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: ${size}
---
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
spec:
  containers:
    - name: pause
      image: ${pause_image}
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: ${name}
EOF
}

echo "::group::a ${fits} claim on the default storage class"
claim fits "$fits"
kubectl -n default wait --for=jsonpath='{.status.phase}'=Bound pvc/fits --timeout=300s
kubectl -n default wait --for=condition=Ready pod/fits --timeout=300s
volume=$(kubectl -n default get pvc fits -o jsonpath='{.spec.volumeName}')
echo "lvs --units b vg0:"
lvs --units b -o lv_name,vg_name,lv_size vg0
size=$(lvs --noheadings --nosuffix --units b -o lv_size "vg0/${volume}" | tr -d '[:space:]')
[ "$size" = "$fits_bytes" ] || fail "claim fits bound ${volume}, whose logical volume is ${size} bytes, want ${fits_bytes}"
echo "localpv-lvm-proof: PASS: the ${fits} claim bound logical volume vg0/${volume} of ${size} bytes"
echo "::endgroup::"

echo "::group::a ${too_big} claim, larger than vg0's free space"
vgs --units b -o vg_name,vg_size,vg_free vg0
claim too-big "$too_big"
for _ in $(seq 1 "$pending_seconds"); do
  phase=$(kubectl -n default get pvc too-big -o jsonpath='{.status.phase}')
  [ "$phase" = Pending ] || fail "claim too-big reached phase ${phase}, want it Pending"
  sleep 1
done
kubectl -n default get pvc too-big
kubectl -n default get events --field-selector involvedObject.name=too-big
bound=$(kubectl -n default get pvc too-big -o jsonpath='{.spec.volumeName}')
[ -z "$bound" ] || fail "claim too-big names volume ${bound}, want none"
echo "lvs --units b vg0:"
lvs --units b -o lv_name,vg_name,lv_size vg0
volumes=$(lvs --noheadings -o lv_name vg0 | tr -d ' ' | grep -c . || true)
[ "$volumes" -eq 1 ] || fail "vg0 holds ${volumes} logical volumes, want only vg0/${volume} of claim fits"
echo "localpv-lvm-proof: PASS: claim too-big stayed Pending for ${pending_seconds}s and vg0 holds no logical volume for it"
echo "::endgroup::"
