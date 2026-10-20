// Package cluster renders what a mitstack k3s node boots from and what its cluster repository starts with.
package cluster

// The user data carries no Hetzner token, no GitHub token and no cluster credential; its secrets are the enrolment token and, on a cluster that hosts the platform, OpenBao's seal key.

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Versions are what the user data installs from and what the cluster repository's seed installs.
type Versions struct {
	K3sVersion, K3sSHA256, K3sInstallerCommit, K3sInstallerSHA256, CiliumVersion, ArgoCDChartVersion string
	KuredChartVersion, SystemUpgradeControllerVersion                                                string
	TraefikChartVersion, CertManagerChartVersion                                                     string
	KyvernoChartVersion                                                                              string
}

// PinnedVersions are the reviewed pins a new server installs; the k3s binary and installer digests are kube-hetzner v3.2.1's.
var PinnedVersions = Versions{
	K3sVersion:                     "v1.36.3+k3s1",
	K3sSHA256:                      "2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5",
	K3sInstallerCommit:             "2d0f82fa2f933cd227fe38e1482558ce4769f464",
	K3sInstallerSHA256:             "ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b",
	CiliumVersion:                  "1.19.3",
	ArgoCDChartVersion:             "10.9.7",
	KuredChartVersion:              "6.1.0",
	SystemUpgradeControllerVersion: "v0.20.2",
	TraefikChartVersion:            "41.6.1",
	CertManagerChartVersion:        "v1.21.2",
	KyvernoChartVersion:            "3.9.1",
}

// UserDataInputs are what one server's user data names: its subscription, issuer, repository, enrolment token and pins.
type UserDataInputs struct {
	SubscriptionID, IssuerURL, ClusterRepoURL, EnrolmentToken string
	Versions                                                  Versions
	HostsPlatform                                             *HostsPlatformInputs
}

const (
	nodeScriptPath  = "/usr/local/sbin/mitstack-hcloud-node"
	enrolScriptPath = "/usr/local/sbin/mitstack-enrol"
	installerPath   = "/usr/local/sbin/mitstack-install-k3s"
	manifestsDir    = "/var/lib/rancher/k3s/server/manifests"
	UnitDir         = "/etc/systemd/system"
	guardRulesPath  = "/etc/mitstack/metadata-guard.nft"

	EnrolUnit = "mitstack-enrol.service"
	guardUnit = "mitstack-metadata-guard.service"

	osPatchUnits = "unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer"

	userDataLimit = 32768

	RootOnlyMode   = "0600"
	worldReadMode  = "0644"
	ExecutableMode = "0700"
)

var (
	k3sVersionRe    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?\+k3s[0-9]+$`)
	SHA256HexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRe        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	chartVersionRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	releaseTagRe    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	httpsURLRe      = regexp.MustCompile(`^https://[^\s'"\\` + "`" + `$]+$`)
	githubRepoURLRe = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$`)
	// LabelValueRe is the shape Hetzner accepts for a label value.
	LabelValueRe = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
)

// PatternCheck holds one rendered value to the shape it must have.
type PatternCheck struct {
	Field, Value string
	Re           *regexp.Regexp
}

// CheckPatterns names the first field out of shape but never its value, since
// the enrolment token is among them.
func CheckPatterns(rendering string, checks []PatternCheck) error {
	for _, c := range checks {
		if !c.Re.MatchString(c.Value) {
			return fmt.Errorf("%s: %s is not in the shape %s", rendering, c.Field, c.Re)
		}
	}
	return nil
}

// validate holds every value to a pattern, since each reaches a shell script, a YAML document or an env file.
func (in UserDataInputs) validate() error {
	if in.HostsPlatform != nil {
		if err := in.HostsPlatform.validate(); err != nil {
			return err
		}
	}
	v := in.Versions
	return CheckPatterns("rendering user data", []PatternCheck{
		{"SubscriptionID", in.SubscriptionID, LabelValueRe},
		{"IssuerURL", in.IssuerURL, httpsURLRe},
		{"ClusterRepoURL", in.ClusterRepoURL, githubRepoURLRe},
		{"EnrolmentToken", in.EnrolmentToken, SHA256HexRe},
		{"K3sVersion", v.K3sVersion, k3sVersionRe},
		{"K3sSHA256", v.K3sSHA256, SHA256HexRe},
		{"K3sInstallerCommit", v.K3sInstallerCommit, commitRe},
		{"K3sInstallerSHA256", v.K3sInstallerSHA256, SHA256HexRe},
		{"CiliumVersion", v.CiliumVersion, chartVersionRe},
		{"ArgoCDChartVersion", v.ArgoCDChartVersion, chartVersionRe},
		{"KuredChartVersion", v.KuredChartVersion, chartVersionRe},
		{"SystemUpgradeControllerVersion", v.SystemUpgradeControllerVersion, releaseTagRe},
	})
}

// CloudInitFile is one write_files entry of a cloud-config document.
type CloudInitFile struct {
	Path        string `yaml:"path"`
	Owner       string `yaml:"owner"`
	Permissions string `yaml:"permissions"`
	Encoding    string `yaml:"encoding,omitempty"`
	Content     string `yaml:"content"`
}

// CloudInitConfig is a cloud-config document's files and the commands it runs once they are written.
type CloudInitConfig struct {
	WriteFiles []CloudInitFile `yaml:"write_files"`
	RunCmd     []string        `yaml:"runcmd"`
}

// RenderUserData renders the same bytes for the same inputs.
func RenderUserData(in UserDataInputs) (string, error) {
	if err := in.validate(); err != nil {
		return "", err
	}
	rootOnly, err := rootOnlyFiles(in)
	if err != nil {
		return "", err
	}
	scripts, err := nodeScriptFiles(in.Versions)
	if err != nil {
		return "", err
	}
	if in.HostsPlatform == nil {
		return UserDataDocument(CloudInitConfig{
			WriteFiles: slices.Concat(rootOnly, scripts, serviceFiles(k3sWaitsForEnrolment)),
			RunCmd:     []string{bootCommand()},
		})
	}
	platform, err := hostsPlatformFiles(in)
	if err != nil {
		return "", err
	}
	return UserDataDocument(CloudInitConfig{
		WriteFiles: slices.Concat(rootOnly, platform, scripts, serviceFiles(nil)),
		RunCmd:     []string{hostsPlatformBootCommand()},
	})
}

// rootOnlyFiles are the k3s config, the boot manifests, the enrolment env and
// the metadata guard's rules, each readable by root alone.
func rootOnlyFiles(in UserDataInputs) ([]CloudInitFile, error) {
	documents := []struct {
		path string
		docs []any
	}{
		{"/etc/rancher/k3s/config.yaml", []any{k3sServerConfig(in.IssuerURL)}},
		{manifestsDir + "/cilium.yaml", []any{ciliumChart(in.Versions.CiliumVersion)}},
		{manifestsDir + "/00-argocd-bootstrap.yaml", []any{argoCDNamespace(), argoCDChart(in.Versions.ArgoCDChartVersion)}},
		{manifestsDir + "/10-cluster-root.yaml", []any{clusterRootApplication(in.ClusterRepoURL)}},
	}
	files := make([]CloudInitFile, 0, len(documents))
	for _, d := range documents {
		content, err := marshalYAMLDocs(d.docs...)
		if err != nil {
			return nil, fmt.Errorf("rendering user data: %s: %w", d.path, err)
		}
		files = append(files, RootFile(d.path, RootOnlyMode, content))
	}
	return append(files,
		RootFile("/etc/mitstack/enrolment.env", RootOnlyMode, enrolmentEnvFile(in)),
		RootFile(guardRulesPath, RootOnlyMode, metadataGuardRules),
	), nil
}

// enrolmentEnvFile spells the repository URL as the root Application does, since
// Argo CD matches a repository credential by URL.
func enrolmentEnvFile(in UserDataInputs) string {
	return "MITSTACK_ENROLMENT_TOKEN=" + in.EnrolmentToken + "\n" +
		"MITSTACK_SUBSCRIPTION_ID=" + in.SubscriptionID + "\n" +
		"MITSTACK_REPOSITORY_URL=" + in.ClusterRepoURL + "\n"
}

func nodeScriptFiles(v Versions) ([]CloudInitFile, error) {
	installer, err := renderInstaller(v)
	if err != nil {
		return nil, err
	}
	scripts := []struct{ path, script string }{
		{nodeScriptPath, nodeScript},
		{enrolScriptPath, enrolScript},
		{installerPath, installer},
	}
	files := make([]CloudInitFile, 0, len(scripts))
	for _, s := range scripts {
		f, err := ScriptFile(s.path, s.script)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

var k3sWaitsForEnrolment = []CloudInitFile{RootFile(UnitDir+"/k3s.service.d/10-mitstack-enrolment.conf", worldReadMode, k3sEnrolmentDropIn)}

// serviceFiles are the systemd units and drop-ins and the apt settings.
func serviceFiles(enrolmentDropIn []CloudInitFile) []CloudInitFile {
	return slices.Concat([]CloudInitFile{RootFile(UnitDir+"/"+EnrolUnit, worldReadMode, enrolUnitFile)}, enrolmentDropIn, []CloudInitFile{
		RootFile(UnitDir+"/"+guardUnit, worldReadMode, guardUnitFile),
		RootFile(UnitDir+"/k3s.service.d/20-mitstack-metadata-guard.conf", worldReadMode, k3sGuardDropIn),
		RootFile(UnitDir+"/apt-daily-upgrade.timer.d/10-mitstack-maintenance-window.conf", worldReadMode, aptDailyUpgradeWindow),
		RootFile("/etc/apt/apt.conf.d/52mitstack-unattended-upgrades", worldReadMode, unattendedUpgradesConfig),
	})
}

// bootCommand is one && chain, since cloud-init runs every runcmd entry even
// after one fails and k3s must install only on an enrolled node.
func bootCommand() string {
	return strings.Join(slices.Concat(bootGuards, []string{nodeScriptPath, "systemctl start " + EnrolUnit}, bootInstall), " && ")
}

// hostsPlatformBootCommand enables k3s without waiting for enrolment, which the timer retries until the platform answers.
func hostsPlatformBootCommand() string {
	return strings.Join(slices.Concat(bootGuards, []string{"install -d -m 0700 " + openBaoDataDir, nodeScriptPath}, bootInstall,
		[]string{"systemctl enable --now " + enrolTimer}), " && ")
}

// MaskSSHCommand stops and masks SSH, since no node and no server a block boots takes a login.
const MaskSSHCommand = "systemctl mask --now ssh.service ssh.socket"

var (
	bootGuards  = []string{MaskSSHCommand, "systemctl daemon-reload", "systemctl enable --now " + guardUnit}
	bootInstall = []string{"systemctl enable --now " + osPatchUnits, "systemctl start --no-block apt-daily.service", installerPath, "systemctl enable --now k3s"}
)

// UserDataDocument marshals doc as a cloud-config document and refuses one over Hetzner's size limit.
func UserDataDocument(doc CloudInitConfig) (string, error) {
	body, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("rendering user data: %w", err)
	}
	userData := "#cloud-config\n" + body
	if len(userData) >= userDataLimit {
		return "", fmt.Errorf("rendering user data: the document is %d bytes, over Hetzner's %d-byte limit", len(userData), userDataLimit)
	}
	return userData, nil
}

// RootFile is a plain-text file owned by root.
func RootFile(path, permissions, content string) CloudInitFile {
	return CloudInitFile{Path: path, Owner: "root:root", Permissions: permissions, Content: content}
}

// stripCommentAndBlankLines drops every comment line but the shebang, and every blank line, since the user data must stay under Hetzner's cap and the source keeps its comments and spacing for readers.
func stripCommentAndBlankLines(script string) string {
	// A here-document that writes a file must hold no blank line, and the final newline ends one on the last line.
	body, newline := strings.CutSuffix(script, "\n")
	lines := strings.Split(body, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !isCommentLine(line) && strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	out := strings.Join(kept, "\n")
	if newline {
		out += "\n"
	}
	return out
}

func isCommentLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	return strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!")
}

// ScriptFile compresses a script without its comment and blank lines onto one base64 line, since as plain text, or wrapped, the scripts would not fit Hetzner's limit.
func ScriptFile(path, script string) (CloudInitFile, error) {
	return CompressedFile(path, ExecutableMode, stripCommentAndBlankLines(script))
}

// CompressedFile writes content gzip-compressed onto one base64 line, which cloud-init decodes back to the same bytes.
func CompressedFile(path, permissions, content string) (CloudInitFile, error) {
	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return CloudInitFile{}, fmt.Errorf("rendering user data: compressing %s: %w", path, err)
	}
	if _, err := zw.Write([]byte(content)); err != nil {
		return CloudInitFile{}, fmt.Errorf("rendering user data: compressing %s: %w", path, err)
	}
	if err := zw.Close(); err != nil {
		return CloudInitFile{}, fmt.Errorf("rendering user data: compressing %s: %w", path, err)
	}
	f := RootFile(path, permissions, base64.StdEncoding.EncodeToString(compressed.Bytes())+"\n")
	f.Encoding = "gz+b64"
	return f, nil
}

func marshalYAML(v any) (string, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("encoding a %T as YAML: %w", v, err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("encoding a %T as YAML: %w", v, err)
	}
	return b.String(), nil
}

func marshalYAMLDocs(docs ...any) (string, error) {
	parts := make([]string, 0, len(docs))
	for _, d := range docs {
		part, err := marshalYAML(d)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "---\n"), nil
}

// k3sConfig sets no token, since k3s generates the server's own on first start.
type k3sConfig struct {
	ClusterInit              bool     `yaml:"cluster-init"`
	Disable                  []string `yaml:"disable"`
	FlannelBackend           string   `yaml:"flannel-backend"`
	DisableNetworkPolicy     bool     `yaml:"disable-network-policy"`
	DisableKubeProxy         bool     `yaml:"disable-kube-proxy"`
	ClusterCIDR              string   `yaml:"cluster-cidr"`
	ServiceCIDR              string   `yaml:"service-cidr"`
	ClusterDNS               string   `yaml:"cluster-dns"`
	KubeletArg               []string `yaml:"kubelet-arg"`
	KubeControllerManagerArg []string `yaml:"kube-controller-manager-arg"`
	KubeAPIServerArg         []string `yaml:"kube-apiserver-arg"`
	SecretsEncryption        bool     `yaml:"secrets-encryption"`
}

// k3sServerConfig takes its kubelet arguments and reservations from kube-hetzner v3.2.1's control-plane defaults.
func k3sServerConfig(issuer string) k3sConfig {
	return k3sConfig{
		ClusterInit:          true,
		Disable:              []string{"local-storage", "traefik"},
		FlannelBackend:       "none",
		DisableNetworkPolicy: true,
		DisableKubeProxy:     false,
		ClusterCIDR:          "10.42.0.0/16",
		ServiceCIDR:          "10.43.0.0/16",
		ClusterDNS:           "10.43.0.10",
		KubeletArg: []string{
			"cloud-provider=external",
			"volume-plugin-dir=/var/lib/kubelet/volumeplugins",
			"kube-reserved=cpu=250m,memory=1500Mi,ephemeral-storage=1Gi",
			"system-reserved=cpu=250m,memory=300Mi",
		},
		KubeControllerManagerArg: []string{"flex-volume-plugin-dir=/var/lib/kubelet/volumeplugins"},
		KubeAPIServerArg: []string{
			"service-account-issuer=" + issuer,
			"service-account-jwks-uri=" + issuer + "/openid/v1/jwks",
		},
		SecretsEncryption: true,
	}
}

// ObjectMeta is the metadata of a Kubernetes object the seed or the user data writes.
type ObjectMeta struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type helmChartSpec struct {
	Chart           string `yaml:"chart"`
	Repo            string `yaml:"repo"`
	Version         string `yaml:"version"`
	TargetNamespace string `yaml:"targetNamespace"`
	Bootstrap       bool   `yaml:"bootstrap,omitempty"`
	ValuesContent   string `yaml:"valuesContent"`
}

type helmChart struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Metadata   ObjectMeta    `yaml:"metadata"`
	Spec       helmChartSpec `yaml:"spec"`
}

type namespace struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   ObjectMeta `yaml:"metadata"`
}

// ciliumValues are kube-hetzner v3.2.1's with Hubble on, and one operator, since one node cannot schedule a second.
//
//go:embed scripts/cilium-values.yaml
var ciliumValues string

// ciliumChart bootstraps Cilium before any pod network exists.
func ciliumChart(version string) helmChart {
	return helmChart{
		APIVersion: "helm.cattle.io/v1",
		Kind:       "HelmChart",
		Metadata:   ObjectMeta{Name: "cilium", Namespace: "kube-system"},
		Spec: helmChartSpec{
			Chart:           "cilium",
			Repo:            "https://helm.cilium.io/",
			Version:         version,
			TargetNamespace: "kube-system",
			Bootstrap:       true,
			ValuesContent:   ciliumValues,
		},
	}
}

func argoCDNamespace() namespace {
	return namespace{APIVersion: "v1", Kind: "Namespace", Metadata: ObjectMeta{Name: "argocd"}}
}

// applicationHealthCheck restores the Application health Argo CD stopped
// assessing in 1.8, so a sync wave waits for each child Application to be
// Healthy, and is one line, since the user data is at Hetzner's limit.
const applicationHealthCheck = `local h=obj.status and obj.status.health or {} return {status=h.status or "Progressing",message=h.message or ""}`

// argoCDChart leaves both notifications objects to the seed and the enrol
// script, and carries the Application health check in argocd-cm from the
// first boot, since cluster-root's first sync is ordered by it.
func argoCDChart(version string) helmChart {
	return helmChart{
		APIVersion: "helm.cattle.io/v1",
		Kind:       "HelmChart",
		Metadata:   ObjectMeta{Name: "argocd", Namespace: "kube-system"},
		Spec: helmChartSpec{
			Chart:           "argo-cd",
			Repo:            "https://argoproj.github.io/argo-helm",
			Version:         version,
			TargetNamespace: "argocd",
			ValuesContent:   "dex: {enabled: false}\nnotifications: {cm: {create: false}, secret: {create: false}}\nconfigs: {cm: {resource.customizations.health.argoproj.io_Application: '" + applicationHealthCheck + "'}}\n",
		},
	}
}

type argoApplication struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   ObjectMeta  `yaml:"metadata"`
	Spec       argoAppSpec `yaml:"spec"`
}

type argoAppSpec struct {
	Project           string                 `yaml:"project"`
	Source            argoSource             `yaml:"source"`
	Destination       argoDestination        `yaml:"destination"`
	SyncPolicy        argoSyncPolicy         `yaml:"syncPolicy"`
	IgnoreDifferences []argoIgnoreDifference `yaml:"ignoreDifferences,omitempty"`
}

// argoSource is either a path in a git repository or a Helm chart in a chart repository.
type argoSource struct {
	RepoURL        string         `yaml:"repoURL"`
	Path           string         `yaml:"path,omitempty"`
	Chart          string         `yaml:"chart,omitempty"`
	TargetRevision string         `yaml:"targetRevision"`
	Helm           *argoHelm      `yaml:"helm,omitempty"`
	Kustomize      *argoKustomize `yaml:"kustomize,omitempty"`
}

type argoKustomize struct {
	Images []string `yaml:"images"`
}

type argoHelm struct {
	ReleaseName string `yaml:"releaseName"`
	Values      string `yaml:"values"`
}

type argoDestination struct {
	Server    string `yaml:"server"`
	Namespace string `yaml:"namespace"`
}

type argoSyncPolicy struct {
	Automated                argoAutomated          `yaml:"automated"`
	SyncOptions              []string               `yaml:"syncOptions,omitempty"`
	ManagedNamespaceMetadata *argoNamespaceMetadata `yaml:"managedNamespaceMetadata,omitempty"`
}

// argoNamespaceMetadata is set on the namespace CreateNamespace=true creates or adopts.
type argoNamespaceMetadata struct {
	Labels map[string]string `yaml:"labels"`
}

// argoIgnoreDifference writes an empty Group for the core API group.
type argoIgnoreDifference struct {
	Group        string   `yaml:"group"`
	Kind         string   `yaml:"kind"`
	Name         string   `yaml:"name,omitempty"`
	Namespace    string   `yaml:"namespace"`
	JSONPointers []string `yaml:"jsonPointers"`
}

type argoAutomated struct {
	Prune      bool `yaml:"prune"`
	SelfHeal   bool `yaml:"selfHeal"`
	AllowEmpty bool `yaml:"allowEmpty,omitempty"`
}

// clusterRootApplication carries no credential, since Argo CD finds the token
// in the Secret of the same repoURL.
func clusterRootApplication(repoURL string) argoApplication {
	return argoApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata:   ObjectMeta{Name: "cluster-root", Namespace: "argocd"},
		Spec: argoAppSpec{
			Project:     "default",
			Source:      argoSource{RepoURL: repoURL, Path: "cluster", TargetRevision: "HEAD"},
			Destination: argoDestination{Server: inClusterServer, Namespace: "argocd"},
			SyncPolicy:  argoSyncPolicy{Automated: argoAutomated{Prune: true, SelfHeal: true}},
		},
	}
}

// installerValues carries K3sVersionPath with "+" escaped, as the release download URL spells it.
type installerValues struct {
	K3sVersion, K3sVersionPath, K3sSHA256, K3sInstallerCommit, K3sInstallerSHA256 string
}

func renderInstaller(v Versions) (string, error) {
	var b bytes.Buffer
	err := installerScript.Execute(&b, installerValues{
		K3sVersion:         v.K3sVersion,
		K3sVersionPath:     strings.ReplaceAll(v.K3sVersion, "+", "%2B"),
		K3sSHA256:          v.K3sSHA256,
		K3sInstallerCommit: v.K3sInstallerCommit,
		K3sInstallerSHA256: v.K3sInstallerSHA256,
	})
	if err != nil {
		return "", fmt.Errorf("rendering the k3s installer: %w", err)
	}
	return b.String(), nil
}
