# k3s-cluster-kit

This repository holds the cluster layer that mitstack's Hetzner blocks build
their k3s nodes from. It is for an engineer who changes what a node boots,
what its cluster repository starts with, or how the node is hardened. A block
is a unit of infrastructure an app subscribes to, and today one block,
[hcloud-k3s-cluster](https://github.com/mitstack-eu/hcloud-k3s-cluster),
imports this module.

The module renders and the block acts. Nothing here calls Hetzner, GitHub or
the platform: each function takes its inputs as values and returns bytes. The
block decides when to render, mints the secrets that go in, and writes the
result to a server or a repository. Keeping the cluster layer in one module
means a hardening fix lands once and reaches every block that builds a node.

## What the module renders

The module holds two Go packages. `github.com/mitstack-eu/k3s-cluster-kit/cluster`
renders, and `github.com/mitstack-eu/k3s-cluster-kit/testutil` holds what the
tests share, as "How you change the module" describes. The `cluster` package's
two entry points render the two things every cluster starts from:

| Function | What it returns | Where it is defined |
|---|---|---|
| `RenderUserData` | The cloud-init document a new server boots with: the k3s config, the boot manifests, the node scripts, the systemd units and the apt settings | `cluster/render.go` |
| `RenderSeed` | The files the block writes into a new cluster repository, keyed by path, which Argo CD then syncs | `cluster/clusterseed.go` |

Both return the same bytes for the same inputs. For example, this renders the
user data of a Cloud server at the reviewed pins:

```go
userData, err := cluster.RenderUserData(cluster.UserDataInputs{
	SubscriptionID: "sub_0123456789ab",
	IssuerURL:      "https://mitstack-oidc-abc.s3.eu-central-1.amazonaws.com/sub_0123456789ab",
	ClusterRepoURL: "https://github.com/acme/shop-cluster",
	EnrolmentToken: enrolmentToken,
	Versions:       cluster.PinnedVersions,
})
```

`UserDataInputs.HostsPlatform` is set only for a cluster that hosts the
platform itself. The user data then also boots OpenBao, cert-manager,
trust-manager, External Secrets, Sealed Secrets and Traefik from k3s's
auto-deploy directory, so the cluster comes up while the platform is down.

## Where each part lives

| Part | Files | What they hold |
|---|---|---|
| The render | `cluster/render.go`, `cluster/scripts.go` | The cloud-config document, the k3s server config, the bootstrap Cilium and Argo CD charts, and the node scripts it embeds from `cluster/scripts/` |
| The cluster seed | `cluster/clusterseed.go`, `cluster/cloudnativepg.go`, `cluster/localpvlvm.go` | The Argo CD Applications and objects a cluster repository starts with, and the components copied from a release of mitstack-eu/cluster-bases, the repository of pinned third-party manifests, into `cluster/clusterbases/` |
| The boot components | `cluster/bootcomponents.go`, `cluster/bootsecrets.go` | What a cluster that hosts the platform starts before Argo CD runs, the Sealed Secrets key pair it boots with, and the Job that initialises OpenBao |
| The node agent | `cluster/scripts/nodeagent/` | The image that runs the node report, the repository-token refresh, the patch check and OpenBao's init, its manifest, and the digest of the signed image the seed pins |
| The hardening | `cluster/units.go`, `cluster/unattendedupgrades.go`, `cluster/admission.go` | The metadata guard that drops pod traffic to Hetzner's metadata service, SSH masked at boot, unattended upgrades in a maintenance window, and the Kyverno admission policies in `cluster/admission/` |
| The mutual TLS | `cluster/clusterbases/openbao/tls.yaml`, `cluster/scripts/nodeagent/openbao.py` | OpenBao's serving certificate from the cluster's own authority, and the node agent's client, which trusts that authority alone |

## Which block code calls it

The block keeps every call that reaches an outside service, and calls the
module wherever it renders or hardens a node. In hcloud-k3s-cluster:

| Block function | File | What it takes from the module |
|---|---|---|
| `createServer` | `resource.go` | `RenderUserData` and `UserDataInputs` for a Cloud server |
| `provisionServer` | `resource.go` | `RenderSeed` for the new cluster repository |
| `pins` | `resource.go` | `Versions` and `PinnedVersions`, unless a test sets its own |
| `ensureLoadBalancer`, `reachProblems`, `clusterFirewall` | `resource.go`, `observe.go`, `dedicated.go` | `LoadBalancerPrivateIP`, `HTTPNodePort` and `HTTPSNodePort`, the address and ports Traefik's seeded values name |
| `holdsSeed`, `ObserveResource` | `repository.go`, `observe.go` | `SeedArgoCDFile`, the seed file whose presence marks a seeded repository |
| `validSubscriptionID`, `runAndRecord` | `identity.go`, `install.go` | `LabelValueRe`, the shape of a Hetzner label value |
| `readHostsPlatform` | `hostsplatform.go` | `DigitsRe`, the shape of a GitHub App number |
| `userDataInputs`, `adaptSeed` | `hostsplatform.go` | `HostsPlatformInputs`, and `HostsPlatformSeed` on a cluster that hosts the platform |
| `prepareInstall`, `prepareInstallOrWait` | `install.go` | `RenderUserData`, `UserDataInputs` and `HostsPlatformInputs` for a dedicated server |
| `beginInstall` | `install.go` | `RenderDedicatedSeed`, the seed with LocalPV-LVM added |
| `renderPostInstall` | `install.go` | `UnitDir` and `ExecutableMode` |
| the rescue read's journal sources | `rescueread.go` | `EnrolUnit` |
| `beginSealedAppKeyWait`, `poll`, `awaitSealedAppKey`, `networkProblems` | `sealedsecrets.go`, `install.go`, `dedicated_observe.go` | `SealedSecretsInputs`, `SealedSecretsInputs.Opens`, `MintSealedSecretsKeyPair`, `ReadSealedAppKey`, `SealedAppKeyFile` and `SealedSecretsCertFile` |
| `renderServeUserData` | `userdata_serve.go` | `UserDataDocument`, `CloudInitConfig`, `CloudInitFile`, `RootFile`, `CompressedFile`, `ScriptFile`, `RootOnlyMode` and `MaskSSHCommand`, for the server that serves a dedicated node's user data |
| `userDataFetch.validate` | `userdata_serve.go` | `CheckPatterns`, `PatternCheck` and `SHA256HexRe` |

## How a release is versioned

A block takes a change only by requiring a newer tag of this module in its
`go.mod`, as `require github.com/mitstack-eu/k3s-cluster-kit v0.1.0`. The
file `.github/version` names the next release. Once a pull request merges and
every CI job passes on `main`, the `release` job tags that commit
`v` followed by the version, unless the tag exists already.

A change to what a node boots bumps `.github/version` in the same pull
request. The block that takes the release then sees the change in its own
test `TestUserData_EachShapeRendersTheRecordedSHA256`, which pins the SHA-256
of each shape's user data.

## How you change the module

The tests compare the user data and the seed byte for byte with the
recordings in `cluster/testdata/golden/`, so an edit to what a node boots
fails them until you record the new bytes on purpose.

The package `github.com/mitstack-eu/k3s-cluster-kit/testutil` holds the
fixtures, the script fakes and the checks that this module's tests and a
block's tests share. A block's tests import it, so each fake exists once:
`testutil/fixtures.go` holds the fixture values, `testutil/userdata.go`
parses a rendered cloud-config, `testutil/scripts.go` runs a script against
a fake platform endpoint or a fake tool, and `testutil/checks.go` holds the
assertions.
[The development page](docs/development.md) lists each script, its test file
and the k3s proofs CI runs. Run the suites from the repository root:

```bash
go vet ./...
go test -race ./...
```
