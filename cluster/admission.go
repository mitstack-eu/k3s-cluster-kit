package cluster

// The admission controls reach the cluster through the repository seed, never the user data, which has no room for them.

import (
	"embed"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	seedKyvernoFile        = "cluster/kyverno.yaml"
	seedProbeNamespaceFile = "cluster/admission-probe-namespace.yaml"
	seedProbeFixturesFile  = "cluster/admission-probe-fixtures.yaml"

	// probeNamespace is where the node report dry-runs each refused fixture.
	probeNamespace    = "mitstack-admission-probe"
	fixturesConfigMap = "admission-fixtures"

	// podSecurityRule names the fixture Pod Security restricted refuses, which no Kyverno policy does.
	podSecurityRule      = "pod-security-restricted"
	podSecurityProbePath = "admission/probes/pod-security-restricted.yaml"

	defaultDenyGenerator = "mitstack-generate-default-deny"

	signaturePolicy           = "mitstack-verify-node-agent-signature"
	seedNodeAgentFixturesFile = "cluster/node-agent-admission-fixtures.yaml"
)

// systemNamespaces are excluded by name from every policy and from Kyverno's webhooks, so a Kyverno outage cannot block a system pod.
var systemNamespaces = []string{
	"kube-system", "kube-public", "kube-node-lease", "argocd", "kyverno", "traefik", "cert-manager", "system-upgrade", "mitstack-metadata-probe", "openbao", "external-secrets", "cnpg-system",
}

// refusingPolicies are the validating policies the platform's verdict names, each with a refused fixture.
var refusingPolicies = []string{
	"mitstack-require-app-label", "mitstack-require-resource-limits", "mitstack-restrict-image-registries",
	"mitstack-require-image-digest", "mitstack-disallow-host-path",
}

//go:embed admission/policies/*.yaml admission/tests/*/refused.yaml admission/tests/mitstack-verify-node-agent-signature/other-identity.yaml admission/probes/pod-security-restricted.yaml
var admissionSource embed.FS

// kyvernoApplication applies server-side, since Kyverno's CRDs are larger than the annotation a client-side apply writes.
func kyvernoApplication(version string) argoApplication {
	app := namespaceCreatingApplication(kyvernoChart(version))
	app.Spec.SyncPolicy.SyncOptions = append(app.Spec.SyncPolicy.SyncOptions, "ServerSideApply=true")
	return app
}

func kyvernoChart(version string) helmChart {
	return helmChart{
		Metadata: ObjectMeta{Name: "kyverno"},
		Spec: helmChartSpec{
			Chart:           "kyverno",
			Repo:            "https://kyverno.github.io/kyverno/",
			Version:         version,
			TargetNamespace: "kyverno",
			ValuesContent:   kyvernoValues(),
		},
	}
}

func kyvernoValues() string {
	return `config:
  webhooks:
    namespaceSelector:
      matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values: [` + strings.Join(systemNamespaces, ", ") + `]
`
}

// admissionSeedFiles are the policies byte for byte, the probe namespace and the fixtures the node report tries.
func admissionSeedFiles() (map[string]string, error) {
	files, err := admissionPolicyFiles()
	if err != nil {
		return nil, err
	}
	fixtures, err := admissionFixtures()
	if err != nil {
		return nil, err
	}
	nodeFixtures, err := nodeAgentFixtures()
	if err != nil {
		return nil, err
	}
	documents, err := marshalSeedFiles(map[string]any{
		seedProbeNamespaceFile:    probeNamespaceDocument(),
		seedProbeFixturesFile:     fixtures,
		seedNodeAgentFixturesFile: nodeFixtures,
	})
	if err != nil {
		return nil, err
	}
	maps.Copy(files, documents)
	return files, nil
}

func admissionPolicyFiles() (map[string]string, error) {
	files := map[string]string{}
	for _, name := range append(slices.Clone(refusingPolicies), defaultDenyGenerator, signaturePolicy) {
		policy, err := admissionSource.ReadFile("admission/policies/" + name + ".yaml")
		if err != nil {
			return nil, fmt.Errorf("rendering the admission policy %s: %w", name, err)
		}
		files["cluster/admission-policy-"+name+".yaml"] = string(policy)
	}
	return files, nil
}

// probeNamespaceDocument enforces Pod Security restricted, so the privileged probe is refused by Pod Security itself.
func probeNamespaceDocument() namespace {
	return namespace{
		APIVersion: "v1",
		Kind:       "Namespace",
		Metadata:   ObjectMeta{Name: probeNamespace, Labels: restrictedPodSecurity()},
	}
}

func restrictedPodSecurity() map[string]string {
	return map[string]string{
		"pod-security.kubernetes.io/enforce":         "restricted",
		"pod-security.kubernetes.io/enforce-version": "latest",
	}
}

// admissionFixtures holds each rule's refused manifest under the rule's name.
func admissionFixtures() (configMap, error) {
	sources := map[string]string{podSecurityRule: podSecurityProbePath}
	for _, name := range refusingPolicies {
		sources[name] = "admission/tests/" + name + "/refused.yaml"
	}
	data := make(map[string]string, len(sources))
	for rule, path := range sources {
		fixture, err := admissionSource.ReadFile(path)
		if err != nil {
			return configMap{}, fmt.Errorf("rendering the admission fixture for %s: %w", rule, err)
		}
		data[rule] = string(fixture)
	}
	return configMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata:   ObjectMeta{Name: fixturesConfigMap, Namespace: probeNamespace},
		Data:       data,
	}, nil
}

// nodeAgentFixtures holds the signature policy's two refused pods, which the node agent dry-runs in mitstack-node.
func nodeAgentFixtures() (configMap, error) {
	data := map[string]string{}
	for rule, file := range map[string]string{signaturePolicy + "-unsigned": "refused.yaml", signaturePolicy + "-other-identity": "other-identity.yaml"} {
		fixture, err := admissionSource.ReadFile("admission/tests/" + signaturePolicy + "/" + file)
		if err != nil {
			return configMap{}, fmt.Errorf("rendering the node agent's admission fixture %s: %w", rule, err)
		}
		data[rule] = string(fixture)
	}
	return configMap{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata:   ObjectMeta{Name: fixturesConfigMap, Namespace: "mitstack-node"},
		Data:       data,
	}, nil
}
