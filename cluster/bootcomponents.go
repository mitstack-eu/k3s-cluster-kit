package cluster

// The boot components are what a cluster that hosts the platform starts from k3s's auto-deploy directory before
// Argo CD runs, and what the seed then hands to Argo CD unchanged.

import (
	"bytes"
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"
)

const (
	openBaoDataDir = "/var/lib/openbao"
	enrolTimer     = "mitstack-enrol.timer"

	seedOpenBaoFile         = "cluster/openbao.yaml"
	seedOpenBaoTLSFile      = "cluster/openbao-tls.yaml"
	seedTrustManagerFile    = "cluster/trust-manager.yaml"
	seedExternalSecretsFile = "cluster/external-secrets.yaml"
	seedSealedSecretsFile   = "cluster/sealed-secrets.yaml"
)

// DigitsRe is the shape of the number GitHub shows for an App or its installation.
var DigitsRe = regexp.MustCompile(`^[0-9]{1,20}$`)

//go:embed clusterbases/openbao/*.yaml clusterbases/cert-manager/*.yaml clusterbases/trust-manager/*.yaml clusterbases/external-secrets/*.yaml clusterbases/traefik/*.yaml clusterbases/sealed-secrets/*.yaml
var bootComponents embed.FS

// HostsPlatformInputs are what the user data of a cluster that hosts the platform adds.
type HostsPlatformInputs struct {
	SealKey, AppID, InstallationID, PublicIPv4 string
	// Recipient is the armored public key the boot Job encrypts OpenBao's root token and recovery key to.
	Recipient     string
	SealedSecrets SealedSecretsInputs
}

func (h HostsPlatformInputs) validate() error {
	err := CheckPatterns("rendering user data", []PatternCheck{
		{"SealKey", h.SealKey, SHA256HexRe},
		{"AppID", h.AppID, DigitsRe},
		{"InstallationID", h.InstallationID, DigitsRe},
	})
	if err != nil {
		return err
	}
	if !isCanonicalIPv4(h.PublicIPv4) {
		return fmt.Errorf("rendering user data: PublicIPv4 %q is not a dotted IPv4 address", h.PublicIPv4)
	}
	if !strings.HasPrefix(h.Recipient, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n") {
		return fmt.Errorf("rendering user data: Recipient is not an armored OpenPGP public key")
	}
	if err := keyPairOf(h.SealedSecrets.KeyPEM, h.SealedSecrets.CertPEM); err != nil {
		return fmt.Errorf("rendering user data: %w", err)
	}
	return nil
}

// bootComponent reads a cluster-bases HelmChart this package carries.
func bootComponent(name string) helmChart {
	var chart helmChart
	if err := yaml.Unmarshal([]byte(bootComponentFile(name, "helmchart.yaml")), &chart); err != nil {
		panic(fmt.Sprintf("clusterbases/%s/helmchart.yaml: %v", name, err))
	}
	return chart
}

func bootComponentFile(name, file string) string {
	raw, err := bootComponents.ReadFile("clusterbases/" + name + "/" + file)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// bootManifest is a cluster-bases manifest without its comments, which hold no YAML block scalar, for the user data's
// size cap.
func bootManifest(name, file string) string {
	return stripCommentAndBlankLines(bootComponentFile(name, file))
}

// bootTraefikChart adds the load balancer's values, which name no image, to the cluster-bases chart.
func bootTraefikChart(publicIPv4 string) helmChart {
	chart := bootComponent("traefik")
	chart.Spec.ValuesContent = traefikValues(publicIPv4) + chart.Spec.ValuesContent
	return chart
}

func restrictedNamespace(name string) namespace {
	return namespace{APIVersion: "v1", Kind: "Namespace", Metadata: ObjectMeta{Name: name, Labels: restrictedPodSecurity()}}
}

type sealKeySecret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   ObjectMeta        `yaml:"metadata"`
	StringData map[string]string `yaml:"stringData"`
}

// bootComponentsFile holds every boot chart, their namespaces and OpenBao's volume in one compressed file, for the user
// data's size cap. Each is a kind k3s can apply at once, so no chart waits on a CRD that 02-openbao-tls.yaml needs.
const bootComponentsFile = "02-boot-components.yaml"

// hostsPlatformFiles are the manifests k3s applies in name order before 10-cluster-root.yaml, the skip file that keeps
// enrolment's platform token out of Argo CD, and the timer that retries enrolment until the platform answers.
func hostsPlatformFiles(in UserDataInputs) ([]CloudInitFile, error) {
	h := in.HostsPlatform
	credential, err := repositoryCredentialManifest(in.ClusterRepoURL, *h)
	if err != nil {
		return nil, err
	}
	boot, err := openBaoBootManifest(in.ClusterRepoURL, *h)
	if err != nil {
		return nil, err
	}
	// The keys stay plain text, so a reader of the user data finds each once; the rest is compressed to fit Hetzner's limit.
	documents := []struct {
		name, verbatim string
		docs           []any
		plain          bool
	}{
		{name: "01-openbao-seal-key.yaml", plain: true, docs: []any{restrictedNamespace("openbao"), sealKeySecret{APIVersion: "v1", Kind: "Secret",
			Metadata: ObjectMeta{Name: "openbao-seal-key", Namespace: "openbao"}, StringData: map[string]string{"key": h.SealKey}}}},
		{name: "01-sealed-secrets-key.yaml", plain: true, docs: []any{sealedSecretsKeySecret(h.SealedSecrets)}},
		{name: bootComponentsFile, verbatim: bootManifest("openbao", "storage.yaml") + "---\n", docs: []any{
			restrictedNamespace("cert-manager"), bootComponent("cert-manager"), bootComponent("trust-manager"),
			restrictedNamespace("external-secrets"), bootComponent("external-secrets"), bootComponent("openbao"),
			bootComponent("sealed-secrets"), restrictedNamespace("traefik"), bootTraefikChart(h.PublicIPv4)}},
		{name: "02-openbao-tls.yaml", verbatim: bootManifest("openbao", "tls.yaml")},
		{name: "03-cluster-repository.yaml", verbatim: credential},
		{name: "04-openbao-boot.yaml", verbatim: boot},
	}
	files := make([]CloudInitFile, 0, len(documents)+2)
	for _, d := range documents {
		content, err := marshalYAMLDocs(d.docs...)
		if err != nil {
			return nil, fmt.Errorf("rendering user data: %s: %w", d.name, err)
		}
		f := RootFile(manifestsDir+"/"+d.name, RootOnlyMode, d.verbatim+content)
		if !d.plain {
			if f, err = CompressedFile(f.Path, RootOnlyMode, f.Content); err != nil {
				return nil, err
			}
		}
		files = append(files, f)
	}
	return append(files,
		RootFile(manifestsDir+"/05-cluster-repository.yaml.skip", RootOnlyMode, ""),
		RootFile(UnitDir+"/"+enrolTimer, worldReadMode, enrolTimerFile),
	), nil
}

// repositoryCredentialTemplate copies the App's key from OpenBao's kv/argocd/github-app, under private-key, and mints
// from it a token that reads the cluster repository alone, refreshed well inside GitHub's hour.
var repositoryCredentialTemplate = template.Must(template.New("credential").Parse(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: openbao-argocd
  namespace: argocd
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: openbao
  namespace: argocd
spec:
  provider:
    vault:
      server: https://openbao.openbao.svc:8200
      caProvider:
        type: ConfigMap
        name: openbao-ca
        key: ca.crt
      path: kv
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: argocd
          serviceAccountRef:
            name: openbao-argocd
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: github-app
  namespace: argocd
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: SecretStore
    name: openbao
  target:
    name: github-app
  data:
    - secretKey: private-key
      remoteRef:
        key: argocd/github-app
        property: private-key
---
apiVersion: generators.external-secrets.io/v1alpha1
kind: GithubAccessToken
metadata:
  name: cluster-repository
  namespace: argocd
spec:
  appID: "{{.AppID}}"
  installID: "{{.InstallationID}}"
  repositories: [{{.Repository}}]
  permissions:
    contents: read
  auth:
    privateKey:
      secretRef:
        name: github-app
        key: private-key
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: cluster-repository
  namespace: argocd
spec:
  refreshInterval: 30m
  target:
    name: cluster-repository
    template:
      metadata:
        labels:
          argocd.argoproj.io/secret-type: repository
      data:
        type: git
        url: {{.RepoURL}}
        username: x-access-token
        password: "{{"{{"}} .token {{"}}"}}"
  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: GithubAccessToken
          name: cluster-repository
`))

func repositoryCredentialManifest(repoURL string, h HostsPlatformInputs) (string, error) {
	m := githubRepoURLRe.FindStringSubmatch(repoURL)
	var b bytes.Buffer
	err := repositoryCredentialTemplate.Execute(&b, struct{ AppID, InstallationID, Repository, RepoURL string }{h.AppID, h.InstallationID, m[2], repoURL})
	if err != nil {
		return "", fmt.Errorf("rendering the repository credential: %w", err)
	}
	return b.String(), nil
}

// enrolTimerFile starts enrolment a minute after boot and five minutes after each failed try; an enrolled node's unit
// stays active, so the timer never starts it again.
const enrolTimerFile = `[Unit]
Description=Retry enrolment with the mitstack platform until it answers

[Timer]
Unit=` + EnrolUnit + `
OnBootSec=1min
OnUnitInactiveSec=5min

[Install]
WantedBy=timers.target
`

// HostsPlatformSeed adds Argo CD's Applications for the booted charts and OpenBao's certificate authority, copied
// exactly so the first sync changes nothing, and leaves cluster-repository to External Secrets.
func HostsPlatformSeed(files map[string]string, publicIPv4 string) error {
	externalSecrets := chartApplication(bootComponent("external-secrets"))
	externalSecrets.Spec.SyncPolicy.SyncOptions = []string{"ServerSideApply=true"}
	documents := map[string]any{
		seedOpenBaoFile:         chartApplication(bootComponent("openbao")),
		seedCertManagerFile:     inCRDWave(namespaceCreatingApplication(bootComponent("cert-manager"))),
		seedTrustManagerFile:    inCRDWave(chartApplication(bootComponent("trust-manager"))),
		seedExternalSecretsFile: externalSecrets,
		seedSealedSecretsFile:   chartApplication(bootComponent("sealed-secrets")),
		seedTraefikFile:         traefikApplicationOf(bootTraefikChart(publicIPv4)),
	}
	apps, err := marshalSeedFiles(documents)
	if err != nil {
		return err
	}
	agent, err := refreshLeavingArgoCDCredential(files[seedNodeAgentFile])
	if err != nil {
		return err
	}
	for path, content := range apps {
		files[path] = content
	}
	files[seedOpenBaoTLSFile] = bootComponentFile("openbao", "tls.yaml")
	files[seedNodeAgentFile] = agent
	return nil
}

// refreshEdits drop the refresh's patch of cluster-repository and tell it so, since the script fails a refused patch,
// and let the namespace reach OpenBao, which the boot Job and the App key's writer run against.
var refreshEdits = []struct{ from, to string }{
	{"rules:\n- apiGroups: [\"\"]\n  resources: [secrets]\n  resourceNames: [cluster-repository]\n  verbs: [patch]\n", "rules: []\n"},
	{"            command: [mitstack-repo-token]\n            env:\n", "            command: [mitstack-repo-token]\n            env:\n            - name: MITSTACK_PATCH_CLUSTER_REPOSITORY\n              value: \"false\"\n"},
	{"  - toEntities: [world]\n", "  - toEndpoints:\n    - matchLabels: {k8s:io.kubernetes.pod.namespace: openbao, app.kubernetes.io/name: openbao}\n    toPorts:\n    - ports: [{port: \"8200\", protocol: TCP}]\n  - toEntities: [world]\n"},
}

func refreshLeavingArgoCDCredential(manifest string) (string, error) {
	for _, e := range refreshEdits {
		if strings.Count(manifest, e.from) != 1 {
			return "", fmt.Errorf("rendering the node agent for a cluster that hosts the platform: %q is not in %s exactly once", e.from, seedNodeAgentFile)
		}
		manifest = strings.Replace(manifest, e.from, e.to, 1)
	}
	return manifest, nil
}
