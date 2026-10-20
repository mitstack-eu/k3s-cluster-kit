# Developing the cluster module

This page is for anyone changing k3s-cluster-kit: where the node's scripts
live, how each test suite runs them, and what CI proves on a real k3s node
before a release is tagged. Every path below is relative to the `cluster/`
package directory, where the tests and the proofs run.

Back to [the README](../README.md).

## Where the node scripts live

Every script the user data writes is a file in `scripts/`, and `scripts.go`
loads each one with `go:embed`. You can read and lint a script as the shell
it is. The node runs what the file holds, without its full-line comments and
blank lines, which `stripCommentAndBlankLines` in `render.go` drops to keep
the user data under Hetzner's 32 KiB cap.

`golden_test.go` renders the user data and the seed for fixed inputs, and
compares them byte for byte with the recordings in `testdata/golden/`. The
seed is the set of files a block writes into a new cluster repository. An
edit to a file either one carries, such as the enrol script or
`node-agent.yaml`, fails that test until you record the new bytes on purpose.

| File in `scripts/` | What it does on the node | Test file |
|---|---|---|
| `mitstack-hcloud-node.sh` | Names the k3s node by its Hetzner server id and binds k3s to the private IP, before k3s is installed | `nodescript_test.go` |
| `mitstack-enrol.sh` | Enrols the cluster with the platform and writes Argo CD's repository and notifications Secrets, the report token's Secret and the `mitstack-node` namespace from the answer | `enrolscript_test.go` |
| `refusal-reason.sh` | Holds the `refusal_reason` function the enrol and repository-token scripts share, which prints the platform's refusal reason as one line of plain text | `refusalreason_test.go` |
| `mitstack-install-k3s.sh` | Installs k3s from bytes checked against the pinned digests, as a Go template the pins fill in | `installerscript_test.go` |
| `mitstack-patch-check.sh` | Writes how far the OS and k3s are behind their patches to `patch-check.json`. The node agent's image carries it and runs it about hourly | `patchcheck_test.go` |
| `cilium-values.yaml` | Holds the Cilium chart's values, which the node's `HelmChart` and the seeded Cilium Application both carry | `render_test.go` |
| `mitstack-scan.py` | Runs kube-bench and kubescape once a day and keeps a summary of each. The node agent's image carries it and starts it on the host | `scanscript_test.go`, `reportscans_test.go` |

The node agent's own files sit in `scripts/nodeagent/`. The node agent is
the image `ghcr.io/mitstack-eu/mitstack-node-agent`, which runs the node
report, the repository-token refresh and the patch check inside the cluster.
Its `Dockerfile` copies `host.sh`, `report.sh`, `repo-token.sh` and
`openbao.py` into `/opt/mitstack/` as the commands `mitstack-host`,
`mitstack-report`, `mitstack-repo-token` and `mitstack-openbao`. Beside them
it copies `collect.sh`, `mitstack-patch-check.sh`, `mitstack-scan.py` and
`refusal-reason.sh`. The image also carries `curl`, `gpg`, `openssl`,
`python3` and kubectl v1.36.3. The tests run each script from a directory
laid out the same way.

| File in `scripts/nodeagent/` | What it does | Test file |
|---|---|---|
| `host.sh` | Runs as `mitstack-host` in the privileged container and runs `collect.sh` in the host's namespaces through `nsenter`, leaving `host.tar` | `reportscript_test.go` |
| `collect.sh` | Collects the host evidence and the admin-configuration reads, dry-runs the admission fixtures, and starts the patch check, a dedicated server's probe and the scan | `reportscript_test.go`, `reportscans_test.go` |
| `report.sh` | Runs as `mitstack-report`, adds its service account's reads and the Argo CD probes to the evidence in `host.tar`, and posts the report | `reportscript_test.go`, `reportcompare_test.go` |
| `repo-token.sh` | Runs as `mitstack-repo-token` and patches the password of each repository Secret | `repotokenscript_test.go` |
| `openbao.py` | Runs as `mitstack-openbao` on mitstack's own cluster, where its `init` initialises OpenBao, its `write-app-key` keeps the GitHub App's key in OpenBao, and its `write-app-secrets` writes each app's sealed values to its namespace's path | `openbaoscript_test.go` |
| `node-agent.yaml` | The objects the seed writes as `cluster/node-agent.yaml` in the cluster repository | `nodeagent_test.go` |
| `digest` | The digest of the signed image the seed pins | `nodeagent_test.go` |

hcloud-k3s-cluster's CI builds and signs the node agent's image from the
release that block requires, because the admission policy
`mitstack-verify-node-agent-signature` trusts that workflow's signature. A new
image therefore takes two releases: one carrying the new sources, which the
block's `main` signs, and one moving `scripts/nodeagent/digest` to the digest
it signed.

### How placeholders are filled

Two files hold a placeholder in `@NAME@` form, which the Go code fills
before the file reaches a node:

| File | Placeholder | What fills it, and with what |
|---|---|---|
| `mitstack-enrol.sh` | `@REFUSAL_REASON@` | `scripts.go`, with the shared `refusal_reason` function |
| `nodeagent/node-agent.yaml` | `@NODE_AGENT_IMAGE@` | `clusterseed.go`, with the image at the digest `scripts/nodeagent/digest` pins |

`refusal-reason.sh` starts with a shebang only so that it lints on its own,
and the splice leaves that line out. The image's repository-token script
sources the file whole instead.

To lint the shell files, run this from the `cluster/` directory:

```bash
shellcheck scripts/*.sh scripts/nodeagent/*.sh scripts/ci/*.sh
```

## How the script suites run

The script suites run the real scripts against local fakes:

| Test file | What it runs | Against what |
|---|---|---|
| `nodescript_test.go` | The rendered node script, with `sh` | A fake metadata service |
| `enrolscript_test.go` | The rendered enrol script | A local HTTPS server that plays the enrolment endpoint. Three cases wait out the script's retries, about 30 seconds each, and they run in parallel |
| `reportscript_test.go` | The image's `mitstack-host` and `mitstack-report` | A local HTTPS server playing the report endpoint. A fake `nsenter` runs the collection in the test's own namespaces, and a fake `journalctl`, a fake `k3s` that also answers as `kubectl`, and fake `ss`, `systemctl` and `nft` answer it |
| `reportcompare_test.go` | The same scripts over the same fakes | Checks that the report carries every field path of the host report kept in `testdata/host-report-3.0.0.sh` |
| `repotokenscript_test.go` | The image's `mitstack-repo-token` | A local HTTPS server playing the refresh endpoint, with `kubectl` answered by the fake `k3s` |
| `nodeagent_test.go` | The seeded node agent's objects, and the probe Job's command | The rights ADR 0087 grants, and a fake `curl`, so one case waits out the pod's 10 seconds |
| `clusterseed_test.go` | The seeded `Application`s | The boot `HelmChart`s they must match |
| `installerscript_test.go` | The rendered installer | Stub `curl`, `uname` and `install` commands |
| `patchcheck_test.go` | The rendered patch check | A fake `k3s`, `apt-get` and `uname`, a scratch `/boot`, and a local HTTPS server that plays the k3s channels and GitHub's release listing, with the clock set by `MITSTACK_NOW` |
| `openbaoscript_test.go` | The image's `mitstack-openbao` | The real python3, gpg and openssl, against a fake OpenBao and a fake GitHub |

All the script suites need `curl` on `PATH`. The enrol, repository-token,
report and patch check suites need `python3` too.

Run the whole suite, or one area of it, from the repository root:

```bash
go test -race ./...
go test -run 'TestEnrolScript' ./...
go test -run 'TestReportScript' ./...
go test -run 'TestGolden' ./...
```

## What CI runs

`.github/workflows/ci.yml` runs on every pull request, every push to `main`
and a manual run. Every job runs on the runner the repository variable
`CI_RUNS_ON` names, `ubicloud-standard-2` by default, from the `cluster/`
directory.

| Job | What it proves |
|---|---|
| `test` | `go vet ./...` and `go test -race ./...` pass |
| `kyverno-test` | Each admission policy gives its accepted and refused fixtures the expected result |
| `localpv-lvm` | A dedicated seed's LocalPV-LVM binds a claim on a real k3s node |
| `openbao-boot` | The recorded user data of a cluster that hosts the platform initialises OpenBao and writes the GitHub App's key into it |
| `node-agent-reads` | The node agent's report container reads the cluster through its service account |
| `release` | On a push to `main`, once every job above passes, tags the commit with the version `.github/version` names |

### How the admission policies are tested

The `kyverno-test` job checks out the repository with `actions/checkout`
pinned by commit. It then downloads `kyverno-cli_v1.19.1_linux_x86_64.tar.gz`
from Kyverno's v1.19.1 release and checks its sha256 before it extracts
anything. The signature policy's test reads the public package
`ghcr.io/mitstack-eu/mitstack-node-agent` with no login. The job runs:

```bash
kyverno test admission/tests
```

### How CI proves the storage on k3s

The seed tests prove the bytes a dedicated server's repository receives, and
only a running node shows what those bytes do. The `localpv-lvm` job
therefore runs `scripts/ci/localpv-lvm-proof.sh` as root on a Ubicloud
runner, which is a disposable VM. The script does this, in order:

1. It creates a 4G loop device and makes volume group `vg0` on it.
2. It installs k3s `v1.36.3+k3s1`, the version the module pins, after
   checking its sha256, and starts it with `local-storage` and `traefik`
   disabled, as the rendered k3s config does.
3. It applies `clusterbases/localpv-lvm/` into `kube-system` and waits for
   the controller and node plugin to roll out.
4. It checks that `openebs-lvm` is the only default storage class.
5. It claims 1Gi with no class named, waits for the claim to bind, and checks
   with `lvs --units b` that its logical volume is 1073741824 bytes.
6. It claims 8Gi, more than `vg0` has free, and checks that the claim stays
   `Pending` for 120 seconds while `vg0` still holds only the first volume.

Each check that fails stops the job with a line starting
`localpv-lvm-proof: FAIL:`, followed by the cluster's pods, claims, events,
LocalPV-LVM logs and `lvs` output. A run that passes prints `lvs` after each
claim and a `localpv-lvm-proof: PASS:` line for each.

### How CI proves OpenBao's boot on k3s

The `openbao-boot` job runs `scripts/ci/openbao-boot-proof.sh` as root on a
Ubicloud runner. It boots the manifests recorded in
`testdata/golden/userdata-hosts-platform.yaml`, which `golden_test.go` holds
to what `RenderUserData` writes, with the test-only keys in `testdata/boot/`.
The script does this, in order:

1. It builds the node agent's image from the commit and puts it where k3s
   imports images at start, since the pinned digest is a release behind
   until the block's `main` signs the new image.
2. It runs a fake GitHub on the host, which mints an installation token for
   any signed JWT and serves the contents API.
3. It writes `01-openbao-seal-key.yaml`, `01-sealed-secrets-key.yaml`,
   `02-boot-components.yaml`, `02-openbao-tls.yaml` and `04-openbao-boot.yaml`
   into k3s's auto-deploy directory. It changes only the image, points the Job
   at the fake GitHub, and shortens OpenBao's serving certificate to an hour,
   renewed two minutes after each issue. It starts k3s `v1.36.3+k3s1` after
   checking its sha256.
4. It waits for the Job `openbao-init` to complete.
5. It reads the authority from the ConfigMap `openbao-ca` and checks that a
   request to `https://openbao.openbao.svc:8200/v1/sys/health` verifies it and
   gets OpenBao's answer, while a plain `http://` request to port 8200 gets
   none.
6. It checks that `bao status` reads `Initialized true` and `Sealed false`.
7. It checks that `openbao-init.asc` holds two PGP messages, which decrypt
   with `testdata/boot/owner-secret.asc`, and that neither the file nor the
   Job's log holds the root token in plain text.
8. With the decrypted root token, it checks that `bao kv get -mount=kv
   -field=private-key argocd/github-app` has the sha256 of
   `testdata/boot/github-app.pem`.
9. It fetches the certificate the controller publishes and checks it is the
   one in `testdata/boot/`. It seals a newly generated `.pem` against it with
   kubeseal 0.40.0, applies it, and checks that the writer moves the key in
   OpenBao to the new file's sha256.
10. It seals a value for each of the slice namespaces `app-a` and `app-b`, and
    checks that each namespace's service account reads its own and is refused
    the other's.
11. It checks that an ExternalSecret in `app-a`, whose store verifies the
    authority, reads Ready and writes the value sealed for `app-a`.
12. It waits up to ten minutes for OpenBao to serve a certificate with a new
    serial number, and checks that OpenBao is still unsealed.

A failed check prints a line starting `openbao-boot-proof: FAIL:`, followed by
the pods, Jobs, certificates and ExternalSecrets, the logs of the Job, the
writers, the Sealed Secrets controller, OpenBao, cert-manager, trust-manager
and External Secrets, and the fake GitHub's log. A run that passes prints an
`openbao-boot-proof: PASS:` line for each of checks 5 to 12.

### How CI proves the node agent's reads on k3s

The `node-agent-reads` job runs `scripts/ci/node-agent-proof.sh` as root. It
boots k3s with `node-agent.yaml` and an image built from the commit, and
checks that the report container's `kubectl get --request-timeout=10s` reads
return the node and the pods in `argocd` through its service account.
