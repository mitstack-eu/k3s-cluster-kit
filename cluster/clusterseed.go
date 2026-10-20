package cluster

// kured reboots only between 02:00 and 03:00 UTC and the k3s upgrade Plan runs only between 03:00 and 05:00 UTC, so a reboot and an upgrade never overlap.

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	seedRepositoryCredentialsFile = "cluster/repository-credentials.yaml"
	repositoryCredentialsDir      = "repository-credentials"
	// seedRepositoryCredentialsReadme keeps the directory in Git while no slice writes into it.
	seedRepositoryCredentialsReadme = repositoryCredentialsDir + "/README.md"
)

const (
	SeedArgoCDFile            = "cluster/argocd.yaml"
	seedCiliumFile            = "cluster/cilium.yaml"
	seedKuredFile             = "cluster/kured.yaml"
	seedUpgradeControllerFile = "cluster/system-upgrade-controller.yaml"
	seedK3sUpgradePlanFile    = "cluster/k3s-upgrade-plan.yaml"
	seedTraefikFile           = "cluster/traefik.yaml"
	seedCertManagerFile       = "cluster/cert-manager.yaml"
	seedClusterIssuerFile     = "cluster/cluster-issuer.yaml"
	seedNotificationsFile     = "cluster/argocd-notifications.yaml"
	seedNodeAgentFile         = "cluster/node-agent.yaml"

	ingressClassName = "traefik"

	// appLabel names a pod's app, which the admission policies require on every pod in an app namespace.
	appLabel = "mitstack.dev/app"

	acmeSolverAppLabel = "acme-http01-solver"

	// inClusterServer is the API server address Argo CD deploys to its own cluster by.
	inClusterServer = "https://kubernetes.default.svc"

	// upgradeNamespace holds the system-upgrade-controller, its service account and its Plans.
	upgradeNamespace = "system-upgrade"
)

// Traefik listens on fixed NodePorts, which ADR 0076 fixes, and trusts PROXY headers from the load balancer's fixed
// private address alone, so the seed names both before the load balancer exists.
const (
	LoadBalancerPrivateIP = "10.255.0.254"
	HTTPNodePort          = 30080
	HTTPSNodePort         = 30081
)

// ciliumRegeneratedSecrets are the kube-system Secrets the Cilium chart generates afresh on every render, each with the data keys that change.
var ciliumRegeneratedSecrets = []struct {
	name     string
	pointers []string
}{
	{"cilium-ca", []string{"/data/ca.crt", "/data/ca.key"}},
	{"hubble-relay-client-certs", []string{"/data/ca.crt", "/data/tls.crt", "/data/tls.key"}},
	{"hubble-server-certs", []string{"/data/ca.crt", "/data/tls.crt", "/data/tls.key"}},
}

// acmesolverDigests holds the quay.io acmesolver image index each cert-manager chart version runs, since the registry policy admits that image only by the exact digest its pinnedImages variable names.
var acmesolverDigests = map[string]string{
	"v1.21.2": "sha256:699b40d622211ab7accad8a21b04c5fbaa1841ef7a12621e8de492dbe27b2503",
}

// upgradeControllerDigests holds the Docker Hub image index of each system-upgrade-controller release, so a re-pushed tag cannot change what the cluster runs.
var upgradeControllerDigests = map[string]string{
	"v0.20.2": "sha256:61b68d4372baf7ae90fb0f879feea1c082381a8b7547cc5ec85d393c497b11cb",
}

// nodeAgentImage names the image main's CI signed by digest, so a moved tag cannot change what the cluster runs.
var nodeAgentImage = "ghcr.io/mitstack-eu/mitstack-node-agent@" + strings.TrimSpace(script("nodeagent/digest"))

var nodeAgentManifest = strings.ReplaceAll(script("nodeagent/node-agent.yaml"), nodeAgentImagePlaceholder, nodeAgentImage)

// RenderSeed renders the seed files keyed by their repository path, the same bytes for the same versions, public IPv4 and repository URL.
func RenderSeed(v Versions, publicIPv4, repoURL string) (map[string]string, error) {
	if err := validateSeedInputs(v, publicIPv4, repoURL); err != nil {
		return nil, err
	}
	files, err := marshalSeedFiles(seedDocuments(v, publicIPv4, repoURL))
	if err != nil {
		return nil, err
	}
	files[seedRepositoryCredentialsReadme] = repositoryCredentialsReadme
	files[seedNodeAgentFile] = nodeAgentManifest
	admission, err := admissionSeedFiles()
	if err != nil {
		return nil, err
	}
	maps.Copy(files, admission)
	database, err := cloudNativePGSeedFiles(repoURL)
	if err != nil {
		return nil, err
	}
	maps.Copy(files, database)
	return files, nil
}

func validateSeedInputs(v Versions, publicIPv4, repoURL string) error {
	err := CheckPatterns("rendering the cluster repository seed", []PatternCheck{
		{"CiliumVersion", v.CiliumVersion, chartVersionRe},
		{"ArgoCDChartVersion", v.ArgoCDChartVersion, chartVersionRe},
		{"KuredChartVersion", v.KuredChartVersion, chartVersionRe},
		{"SystemUpgradeControllerVersion", v.SystemUpgradeControllerVersion, releaseTagRe},
		{"K3sVersion", v.K3sVersion, k3sVersionRe},
		{"TraefikChartVersion", v.TraefikChartVersion, chartVersionRe},
		{"CertManagerChartVersion", v.CertManagerChartVersion, releaseTagRe},
		{"KyvernoChartVersion", v.KyvernoChartVersion, chartVersionRe},
	})
	if err != nil {
		return err
	}
	if _, ok := acmesolverDigests[v.CertManagerChartVersion]; !ok {
		return fmt.Errorf("rendering the cluster repository seed: no acmesolver digest is recorded for CertManagerChartVersion %s", v.CertManagerChartVersion)
	}
	if _, ok := upgradeControllerDigests[v.SystemUpgradeControllerVersion]; !ok {
		return fmt.Errorf("rendering the cluster repository seed: no system-upgrade-controller digest is recorded for SystemUpgradeControllerVersion %s", v.SystemUpgradeControllerVersion)
	}
	if !isCanonicalIPv4(publicIPv4) {
		return fmt.Errorf("rendering the cluster repository seed: PublicIPv4 %q is not a dotted IPv4 address", publicIPv4)
	}
	if !strings.HasPrefix(repoURL, "https://") || strings.ContainsAny(repoURL, " \t\r\n") {
		return fmt.Errorf("rendering the cluster repository seed: the repository URL %q is not an https URL", repoURL)
	}
	return nil
}

// isCanonicalIPv4 refuses any spelling but the dotted one, since Traefik publishes the address exactly as given.
func isCanonicalIPv4(address string) bool {
	parsed, err := netip.ParseAddr(address)
	return err == nil && parsed.Is4() && parsed.String() == address
}

func seedDocuments(v Versions, publicIPv4, repoURL string) map[string]any {
	return map[string]any{
		SeedArgoCDFile:                argoCDApplication(v.ArgoCDChartVersion),
		seedCiliumFile:                ciliumApplication(v.CiliumVersion),
		seedKuredFile:                 chartApplication(kuredChart(v.KuredChartVersion)),
		seedUpgradeControllerFile:     inCRDWave(upgradeControllerApplication(v.SystemUpgradeControllerVersion)),
		seedK3sUpgradePlanFile:        k3sUpgradePlan(k3sChannel(v.K3sVersion)),
		seedTraefikFile:               traefikApplication(v.TraefikChartVersion, publicIPv4),
		seedCertManagerFile:           inCRDWave(namespaceCreatingApplication(certManagerChart(v.CertManagerChartVersion))),
		seedClusterIssuerFile:         letsEncryptIssuer(),
		seedNotificationsFile:         argoCDNotifications(),
		seedKyvernoFile:               inCRDWave(kyvernoApplication(v.KyvernoChartVersion)),
		seedRepositoryCredentialsFile: repositoryCredentialsApplication(repoURL),
	}
}

// repositoryCredentialsApplication ignores only the token the repository-token refresh patches, so self-heal reverts any other change to a slice's Secret, and allowEmpty lets the last slice's removal prune its Secret and grant.
func repositoryCredentialsApplication(repoURL string) argoApplication {
	return argoApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata:   ObjectMeta{Name: "repository-credentials", Namespace: "argocd"},
		Spec: argoAppSpec{
			Project:     "default",
			Source:      argoSource{RepoURL: repoURL, Path: repositoryCredentialsDir, TargetRevision: "HEAD"},
			Destination: argoDestination{Server: inClusterServer, Namespace: "argocd"},
			SyncPolicy: argoSyncPolicy{
				Automated:   argoAutomated{Prune: true, SelfHeal: true, AllowEmpty: true},
				SyncOptions: []string{"RespectIgnoreDifferences=true"},
			},
			IgnoreDifferences: []argoIgnoreDifference{{Kind: "Secret", Namespace: "argocd", JSONPointers: []string{"/data/password"}}},
		},
	}
}

const repositoryCredentialsReadme = `# Repository credentials

Each app slice commits three files here: its app's Argo CD repository Secret,
and the Role and RoleBinding that let the repository-token refresh patch that
Secret's token.

The Application in ` + "`cluster/repository-credentials.yaml`" + ` syncs this
directory. It applies only JSON and YAML files, so it never applies this
README, which keeps the directory in Git while no slice writes here.
`

// crdWave is the sync wave of an Application that installs CRDs, ahead of Argo CD's default wave 0, where the resources of the kinds it defines apply.
const crdWave = "-1"

// inCRDWave puts app in crdWave, so cluster-root applies the k3s upgrade Plan, the ClusterIssuer and the Kyverno policies only once the Application that defines their kind is Healthy.
func inCRDWave(app argoApplication) argoApplication {
	app.Metadata.Annotations = map[string]string{"argocd.argoproj.io/sync-wave": crdWave}
	return app
}

func marshalSeedFiles(documents map[string]any) (map[string]string, error) {
	files := make(map[string]string, len(documents))
	for path, doc := range documents {
		content, err := marshalYAML(doc)
		if err != nil {
			return nil, fmt.Errorf("rendering %s: %w", path, err)
		}
		files[path] = content
	}
	return files, nil
}

// argoCDApplication applies server-side, since Argo CD's own CRDs are larger than the 262,144-byte annotation a client-side apply writes.
func argoCDApplication(version string) argoApplication {
	app := chartApplication(argoCDChart(version))
	app.Spec.SyncPolicy.SyncOptions = []string{"ServerSideApply=true"}
	return app
}

// ciliumApplication ignores the Secrets Cilium regenerates, since comparing them would never settle and selfHeal would rotate the certificates on every sync.
func ciliumApplication(version string) argoApplication {
	app := chartApplication(ciliumChart(version))
	app.Spec.SyncPolicy.SyncOptions = []string{"RespectIgnoreDifferences=true"}
	for _, s := range ciliumRegeneratedSecrets {
		app.Spec.IgnoreDifferences = append(app.Spec.IgnoreDifferences, argoIgnoreDifference{
			Kind: "Secret", Name: s.name, Namespace: "kube-system", JSONPointers: s.pointers,
		})
	}
	return app
}

// namespaceCreatingApplication asks Argo CD to create the chart's namespace, since a fresh server has none and Argo CD creates one only when asked.
func namespaceCreatingApplication(chart helmChart) argoApplication {
	app := chartApplication(chart)
	app.Spec.SyncPolicy.SyncOptions = []string{"CreateNamespace=true"}
	return app
}

// chartApplication copies chart's name, version, values and namespace exactly, since for a chart k3s installs at boot any difference would make Argo CD's first sync change what runs.
func chartApplication(chart helmChart) argoApplication {
	return argoApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata:   ObjectMeta{Name: chart.Metadata.Name, Namespace: "argocd"},
		Spec: argoAppSpec{
			Project: "default",
			Source: argoSource{
				RepoURL:        chart.Spec.Repo,
				Chart:          chart.Spec.Chart,
				TargetRevision: chart.Spec.Version,
				Helm:           &argoHelm{ReleaseName: chart.Metadata.Name, Values: chart.Spec.ValuesContent},
			},
			Destination: argoDestination{Server: inClusterServer, Namespace: chart.Spec.TargetNamespace},
			SyncPolicy:  argoSyncPolicy{Automated: argoAutomated{Prune: true, SelfHeal: true}},
		},
	}
}

// kuredValues forces the reboot once a drain is blocked for 15 minutes, so kured never leaves the node cordoned, and quotes each time, since YAML 1.1 reads an unquoted 02:00 as a number.
const kuredValues = `configuration:
  period: "5m"
  rebootSentinel: "/var/run/reboot-required"
  startTime: "02:00"
  endTime: "03:00"
  timeZone: "UTC"
  drainTimeout: "15m"
  forceReboot: true
`

// kuredChart is the kured chart, which Argo CD installs from the seed and k3s never does.
func kuredChart(version string) helmChart {
	return helmChart{
		Metadata: ObjectMeta{Name: "kured"},
		Spec: helmChartSpec{
			Chart:           "kured",
			Repo:            "https://kubereboot.github.io/charts",
			Version:         version,
			TargetNamespace: "kube-system",
			ValuesContent:   kuredValues,
		},
	}
}

// traefikValues run one non-root Traefik pod behind the load balancer's NodePorts, trusting PROXY headers from it
// alone, with externalTrafficPolicy Local so kube-proxy keeps its source address, and publish publicIPv4 on each
// Ingress in place of the NodePort Service, which carries no address to publish.
func traefikValues(publicIPv4 string) string {
	trusted := `
    proxyProtocol:
      trustedIPs: ["` + LoadBalancerPrivateIP + `"]`
	return `deployment:
  kind: Deployment
  replicas: 1
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
ports:
  web:
    nodePort: ` + strconv.Itoa(HTTPNodePort) + trusted + `
  websecure:
    nodePort: ` + strconv.Itoa(HTTPSNodePort) + trusted + `
  metrics: null
metrics:
  prometheus: null
service:
  spec:
    type: NodePort
    externalTrafficPolicy: Local
ingressClass:
  enabled: true
  name: ` + ingressClassName + `
podSecurityContext:
  runAsUser: 65532
  runAsGroup: 65532
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
providers:
  kubernetesIngress:
    publishedService:
      enabled: false
    ingressEndpoint:
      ip: "` + publicIPv4 + `"
`
}

func traefikApplication(version, publicIPv4 string) argoApplication {
	return traefikApplicationOf(traefikChart(version, publicIPv4))
}

// traefikApplicationOf labels the traefik namespace for the restricted Pod Security level, which a pod off the host network can meet.
func traefikApplicationOf(chart helmChart) argoApplication {
	app := namespaceCreatingApplication(chart)
	app.Spec.SyncPolicy.ManagedNamespaceMetadata = &argoNamespaceMetadata{Labels: restrictedPodSecurity()}
	return app
}

// traefikChart is the Traefik chart into the traefik namespace, in place of k3s's bundled Traefik.
func traefikChart(version, publicIPv4 string) helmChart {
	return helmChart{
		Metadata: ObjectMeta{Name: "traefik"},
		Spec: helmChartSpec{
			Chart:           "traefik",
			Repo:            "https://traefik.github.io/charts",
			Version:         version,
			TargetNamespace: "traefik",
			ValuesContent:   traefikValues(publicIPv4),
		},
	}
}

// certManagerValues install the CRDs with the chart and run the HTTP-01 solver from its upstream repository by the digest recorded for version.
func certManagerValues(version string) string {
	return `crds:
  enabled: true
acmesolver:
  image:
    digest: ` + acmesolverDigests[version] + `
`
}

// certManagerChart is the cert-manager chart into the cert-manager namespace.
func certManagerChart(version string) helmChart {
	return helmChart{
		Metadata: ObjectMeta{Name: "cert-manager"},
		Spec: helmChartSpec{
			Chart:           "cert-manager",
			Repo:            "https://charts.jetstack.io",
			Version:         version,
			TargetNamespace: "cert-manager",
			ValuesContent:   certManagerValues(version),
		},
	}
}

// clusterIssuer is cert-manager's cert-manager.io/v1 ClusterIssuer, as far as an ACME issuer with HTTP-01 solvers goes.
type clusterIssuer struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   ObjectMeta        `yaml:"metadata"`
	Spec       clusterIssuerSpec `yaml:"spec"`
}

type clusterIssuerSpec struct {
	ACME acmeIssuer `yaml:"acme"`
}

type acmeIssuer struct {
	Server              string       `yaml:"server"`
	PrivateKeySecretRef secretRef    `yaml:"privateKeySecretRef"`
	Solvers             []acmeSolver `yaml:"solvers"`
}

type secretRef struct {
	Name string `yaml:"name"`
}

type acmeSolver struct {
	HTTP01 acmeHTTP01 `yaml:"http01"`
}

type acmeHTTP01 struct {
	Ingress acmeHTTP01Ingress `yaml:"ingress"`
}

type acmeHTTP01Ingress struct {
	IngressClassName string              `yaml:"ingressClassName"`
	ServiceType      string              `yaml:"serviceType,omitempty"`
	PodTemplate      *acmeSolverTemplate `yaml:"podTemplate,omitempty"`
}

type acmeSolverTemplate struct {
	Metadata acmeSolverTemplateMeta `yaml:"metadata"`
}

type acmeSolverTemplateMeta struct {
	Labels map[string]string `yaml:"labels"`
}

// letsEncryptIssuer issues from Let's Encrypt's production directory, solving HTTP-01 through Traefik's IngressClass with a solver pod the admission policies admit, behind a ClusterIP Service, since an app slice's quota allows no NodePort Service.
func letsEncryptIssuer() clusterIssuer {
	return clusterIssuer{
		APIVersion: "cert-manager.io/v1",
		Kind:       "ClusterIssuer",
		Metadata: ObjectMeta{
			Name:        "letsencrypt-production",
			Annotations: map[string]string{"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"},
		},
		Spec: clusterIssuerSpec{ACME: acmeIssuer{
			Server:              "https://acme-v02.api.letsencrypt.org/directory",
			PrivateKeySecretRef: secretRef{Name: "letsencrypt-production-account-key"},
			Solvers:             []acmeSolver{{HTTP01: acmeHTTP01{Ingress: traefikSolverIngress()}}},
		}},
	}
}

func traefikSolverIngress() acmeHTTP01Ingress {
	return acmeHTTP01Ingress{
		IngressClassName: ingressClassName,
		ServiceType:      "ClusterIP",
		PodTemplate: &acmeSolverTemplate{Metadata: acmeSolverTemplateMeta{
			Labels: map[string]string{appLabel: acmeSolverAppLabel},
		}},
	}
}

type configMap struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   ObjectMeta        `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

// notificationsService's bearer is the $platform-token key of argocd-notifications-secret, so no token is in the repository.
const notificationsService = `url: https://api.mitstack.dev/v1/gitops-notifications
headers:
  - name: Authorization
    value: Bearer $platform-token
  - name: Content-Type
    value: application/json
`

// notificationsTemplate posts the eight stored fields through toJson, with the revision the reported operation synced, falling back to the compared revision, and "" for the phase and message of an Application with no operationState.
const notificationsTemplate = `webhook:
  mitstack:
    method: POST
    body: |
      {
        "app": {{toJson .app.metadata.name}},
        "project": {{toJson .app.spec.project}},
        "sync": {{toJson .app.status.sync.status}},
        "revision": {{toJson (dig "operationState" "syncResult" "revision" .app.status.sync.revision .app.status)}},
        "health": {{toJson .app.status.health.status}},
        "phase": {{toJson (dig "operationState" "phase" "" .app.status)}},
        "message": {{toJson (dig "operationState" "message" "" .app.status)}},
        "reconciledAt": {{toJson .app.status.reconciledAt}}
      }
`

// on-deployed fires once per synced revision, so a resync of it posts nothing new.
const (
	triggerOnDeployed = `- when: app.status.operationState != nil and app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'
  oncePer: app.status.operationState?.syncResult?.revision
  send: [mitstack]
`
	triggerOnSyncFailed = `- when: app.status.operationState != nil and app.status.operationState.phase in ['Error', 'Failed']
  send: [mitstack]
`
	triggerOnHealthDegraded = `- when: app.status.health.status == 'Degraded'
  send: [mitstack]
`
)

// notificationsSubscriptions selects every Application, and the engine takes a recipient's text before ':' as the service, so mitstack names the webhook.
const notificationsSubscriptions = `- recipients: [mitstack]
  triggers: [on-deployed, on-sync-failed, on-health-degraded]
`

// argoCDNotifications is argocd-notifications-cm, posting every Application's sync outcome to the platform.
func argoCDNotifications() configMap {
	return configMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata:   ObjectMeta{Name: "argocd-notifications-cm", Namespace: "argocd"},
		Data: map[string]string{
			"service.webhook.mitstack":   notificationsService,
			"template.mitstack":          notificationsTemplate,
			"trigger.on-deployed":        triggerOnDeployed,
			"trigger.on-sync-failed":     triggerOnSyncFailed,
			"trigger.on-health-degraded": triggerOnHealthDegraded,
			"subscriptions":              notificationsSubscriptions,
		},
	}
}

// upgradeControllerApplication syncs the system-upgrade-controller repository's root kustomization at the tag, with the controller's image set to the same tag and its recorded digest, since a tag's own kustomization names the release before it.
func upgradeControllerApplication(tag string) argoApplication {
	return argoApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata:   ObjectMeta{Name: "system-upgrade-controller", Namespace: "argocd"},
		Spec: argoAppSpec{
			Project: "default",
			Source: argoSource{
				RepoURL:        "https://github.com/rancher/system-upgrade-controller",
				Path:           ".",
				TargetRevision: tag,
				Kustomize:      &argoKustomize{Images: []string{"rancher/system-upgrade-controller:" + tag + "@" + upgradeControllerDigests[tag]}},
			},
			Destination: argoDestination{Server: inClusterServer, Namespace: upgradeNamespace},
			SyncPolicy:  argoSyncPolicy{Automated: argoAutomated{Prune: true, SelfHeal: true}},
		},
	}
}

// k3sChannel is the release channel of the minor of a version already in k3sVersionRe's shape, such as .../channels/v1.36 for v1.36.3+k3s1.
func k3sChannel(k3sVersion string) string {
	m := k3sMinorRe.FindStringSubmatch(k3sVersion)
	return "https://update.k3s.io/v1-release/channels/v" + m[1] + "." + m[2]
}

var k3sMinorRe = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.`)

// upgradePlan is the system-upgrade-controller's upgrade.cattle.io/v1 Plan.
type upgradePlan struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   ObjectMeta `yaml:"metadata"`
	Spec       planSpec   `yaml:"spec"`
}

type planSpec struct {
	Concurrency        int              `yaml:"concurrency"`
	Cordon             bool             `yaml:"cordon"`
	NodeSelector       planNodeSelector `yaml:"nodeSelector"`
	ServiceAccountName string           `yaml:"serviceAccountName"`
	Upgrade            planUpgrade      `yaml:"upgrade"`
	Channel            string           `yaml:"channel"`
	Window             planWindow       `yaml:"window"`
}

type planNodeSelector struct {
	MatchExpressions []planExpression `yaml:"matchExpressions"`
}

type planExpression struct {
	Key      string `yaml:"key"`
	Operator string `yaml:"operator"`
}

type planUpgrade struct {
	Image string `yaml:"image"`
}

type planWindow struct {
	Days      []string `yaml:"days"`
	StartTime string   `yaml:"startTime"`
	EndTime   string   `yaml:"endTime"`
	TimeZone  string   `yaml:"timeZone"`
}

// k3sUpgradePlan names no version, since a committed version would take precedence over the channel, and skips Argo CD's dry run, since the Plan CRD is missing until the controller registers it.
func k3sUpgradePlan(channel string) upgradePlan {
	return upgradePlan{
		APIVersion: "upgrade.cattle.io/v1",
		Kind:       "Plan",
		Metadata: ObjectMeta{
			Name:        "k3s-server",
			Namespace:   upgradeNamespace,
			Annotations: map[string]string{"argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"},
		},
		Spec: planSpec{
			Concurrency: 1,
			Cordon:      true,
			NodeSelector: planNodeSelector{MatchExpressions: []planExpression{
				{Key: "node-role.kubernetes.io/control-plane", Operator: "Exists"},
			}},
			ServiceAccountName: "system-upgrade",
			Upgrade:            planUpgrade{Image: "rancher/k3s-upgrade"},
			Channel:            channel,
			Window: planWindow{
				Days:      []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				TimeZone:  "UTC",
			},
		},
	}
}
