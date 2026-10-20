// Package testutil holds the fixtures, script fakes and checks the cluster package's tests and its blocks' tests share.
package testutil

import (
	"regexp"
)

const (
	RedactedValue = "<redacted>"
)

var (
	MadeAtShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

const (
	DedicatedServerFile     = "dedicated-server.json"
	FixtureUplink           = "enp5s0"
	FixtureVSwitchInterface = FixtureUplink + ".4000"
	FixtureVSwitchGateway   = "10.254.0.1"
)

const (
	FixtureSealKey        = "8d26485ad7c5645f1cf12799be1b701d3cccc5cfe56fe967dbf282199e1af1ce"
	FixtureGitHubAppID    = "1234567"
	FixtureInstallationID = "171311443"
	BootDir               = "/var/lib/rancher/k3s/server/manifests"
	SealKeyFile           = BootDir + "/01-openbao-seal-key.yaml"
)

var HexSealKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	SeedArgoCDPath            = "cluster/argocd.yaml"
	SeedCiliumPath            = "cluster/cilium.yaml"
	SeedKuredPath             = "cluster/kured.yaml"
	SeedUpgradeControllerPath = "cluster/system-upgrade-controller.yaml"
	SeedK3sUpgradePlanPath    = "cluster/k3s-upgrade-plan.yaml"
	SeedTraefikPath           = "cluster/traefik.yaml"
	SeedNotificationsPath     = "cluster/argocd-notifications.yaml"
	FixtureIngressIPv4        = "203.0.113.10"
)

const (
	// Every character of the first eight is in the base32 alphabet, so a
	// bucket name derived from the id could contain them.
	FixtureSubID    = "abcd2345-6f7a-4b2c-9d3e-5f6a7b2c3d4e"
	FixtureAppName  = "orbitdemo"
	FixtureOwner    = "acme"
	FixtureRepoName = FixtureAppName + "-cluster"
	FixtureRepo     = FixtureOwner + "/" + FixtureRepoName
	FixtureRepoURL  = "https://github.com/" + FixtureRepo
	OtherAppName    = "otherapp"

	FixtureBucket         = "mitstack-oidc-abcdefghijklmnopqrstuvwxyz"
	FixtureEnrolmentToken = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
)

var WantSeedPaths = []string{
	"cluster-bases/cloudnative-pg/cloudnative-pg.yaml", "cluster-bases/cloudnative-pg/namespace.yaml",
	"cluster/admission-policy-mitstack-disallow-host-path.yaml",
	"cluster/admission-policy-mitstack-generate-default-deny.yaml",
	"cluster/admission-policy-mitstack-require-app-label.yaml",
	"cluster/admission-policy-mitstack-require-image-digest.yaml",
	"cluster/admission-policy-mitstack-require-resource-limits.yaml",
	"cluster/admission-policy-mitstack-restrict-image-registries.yaml",
	"cluster/admission-policy-mitstack-verify-node-agent-signature.yaml",
	"cluster/admission-probe-fixtures.yaml", "cluster/admission-probe-namespace.yaml",
	"cluster/argocd-notifications.yaml",
	"cluster/argocd.yaml", "cluster/cert-manager.yaml", "cluster/cilium.yaml", "cluster/cloudnative-pg.yaml", "cluster/cluster-issuer.yaml",
	"cluster/k3s-upgrade-plan.yaml", "cluster/kured.yaml", "cluster/kyverno.yaml", "cluster/network-policy-mitstack-database-slices.yaml",
	"cluster/node-agent-admission-fixtures.yaml", "cluster/node-agent.yaml", "cluster/repository-credentials.yaml", "cluster/system-upgrade-controller.yaml",
	"cluster/traefik.yaml", "repository-credentials/README.md",
}

const (
	EnrolScriptDirEnv        = "MITSTACK_ENROLMENT_DIR"
	EnrolScriptEnvFile       = "enrolment.env"
	EnrolScriptJSONFile      = "enrolment.json"
	EnrolManifestsDirEnv     = "MITSTACK_K3S_MANIFESTS_DIR"
	EnrolManifestsDirDefault = "/var/lib/rancher/k3s/server/manifests"
	ReportScriptURLEnv       = "MITSTACK_REPORT_URL"
	ReportJournalctlEnv      = "MITSTACK_JOURNALCTL"
	ReportEndpointPath       = "/v1/cluster-reports"
	ReportCloudInitLogEnv    = "MITSTACK_CLOUD_INIT_LOG"
	ReportK3sEnv             = "MITSTACK_K3S"
	ReportStateDirEnv        = "MITSTACK_STATE_DIR"
	ReportSystemctlEnv       = "MITSTACK_SYSTEMCTL"
	K3sRefused               = "The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?"
	EnrolResponseBody        = "{\n  \"repositoryToken\": \"enrol-sentinel-repository-token-0001\",\n  \"repositoryTokenExpiresAt\": \"2026-10-01T10:14:03Z\",\n" +
		"  \"reportToken\": \"enrol-sentinel-report-token-0001\",\n  \"notificationToken\": \"enrol-sentinel-notification-token-0001\"\n}\n"
	FixtureRepositoryToken          = "sentinel-cluster-repository-token-0003"
	FixtureNotificationToken        = "6e6f74696669636174696f6e2d73656e74696e656c2d746f6b656e2d30303034"
	FixtureRepositoryTokenExpiresAt = "2026-10-01T10:14:03Z"
	FixtureReportToken              = "report-sentinel-token-0002"
)

const (
	EnrolEndpointPath   = "/v1/cluster-enrolments"
	RefreshEndpointPath = "/v1/cluster-repository-tokens"
)

func IssuerURLFor(bucket, subID string) string {
	return "https://" + bucket + ".s3.eu-central-1.amazonaws.com/" + subID
}
