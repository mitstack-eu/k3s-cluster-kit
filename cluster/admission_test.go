package cluster

// admission_test.go holds each admission policy and its Kyverno fixtures to the isolation control it enforces.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	admissionPoliciesDir    = "admission/policies"
	admissionTestsDir       = "admission/tests"
	admissionProbeFile      = "admission/probes/pod-security-restricted.yaml"
	admissionProbeNamespace = "mitstack-admission-probe"
	admissionGeneratorName  = "mitstack-generate-default-deny"
	admissionSyncOptions    = "SkipDryRunOnMissingResource=true"
)

var (
	// admissionValidatingPolicies are the five refusals the platform's verdict hard-codes by name.
	admissionValidatingPolicies = []string{
		"mitstack-require-app-label", "mitstack-require-resource-limits", "mitstack-restrict-image-registries",
		"mitstack-require-image-digest", "mitstack-disallow-host-path",
	}
	admissionPolicyNames = append(slices.Clone(admissionValidatingPolicies), admissionGeneratorName, signaturePolicy)

	admissionSystemNamespaces = []string{
		"kube-system", "kube-public", "kube-node-lease", "argocd", "kyverno", "traefik", "cert-manager", "system-upgrade", "mitstack-metadata-probe", "openbao", "external-secrets", "cnpg-system",
	}
	admissionStandards = []string{"Pod Security Standards", "CIS Kubernetes Benchmark", "NSA and CISA Kubernetes Hardening Guide"}

	admissionControllers = []string{"deployments", "statefulsets", "daemonsets", "jobs", "cronjobs", "replicasets"}
	quotedCEL            = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
)

func admissionFile(t *testing.T, path ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path...))
	fatalIf(t, err != nil, "reading the admission file: %v", err)
	return string(raw)
}

func admissionPolicy(t *testing.T, name string) map[string]any {
	t.Helper()
	path := filepath.Join(admissionPoliciesDir, name+".yaml")
	return yamlMap(t, path, admissionFile(t, path))
}

func admissionFixture(t *testing.T, policy, file string) map[string]any {
	t.Helper()
	path := filepath.Join(admissionTestsDir, policy, file)
	return yamlMap(t, path, admissionFile(t, path))
}

func fileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	fatalIf(t, err != nil, "listing %s: %v", dir, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func TestAdmission_PoliciesAreTheSixTheVerdictNamesAndTheNodeAgentSignature(t *testing.T) {
	var want []string
	for _, name := range admissionPolicyNames {
		want = append(want, name+".yaml")
	}
	slices.Sort(want)

	got := fileNames(t, admissionPoliciesDir)

	failIf(t, !slices.Equal(got, want), "%s holds %v, want exactly one file per policy: %v", admissionPoliciesDir, got, want)
}

func TestAdmission_EveryPolicyHasAKyvernoTestDirectoryAndOnlyThePinnedImageTestsBesides(t *testing.T) {
	want := slices.Sorted(slices.Values(append(slices.Clone(admissionPolicyNames), "acme-http01-solver", "cloudnative-pg")))

	got := fileNames(t, admissionTestsDir)

	failIf(t, !slices.Equal(got, want), "%s holds %v, want one directory per policy, the ACME solver pod test and the CloudNativePG pod test: %v", admissionTestsDir, got, want)
}

func TestAdmission_EachPolicyTestHoldsAnAcceptedAndARefusedFixtureAndTheirExpectedResults(t *testing.T) {
	for _, policy := range admissionValidatingPolicies {
		t.Run(policy, func(t *testing.T) {
			short := strings.TrimPrefix(policy, "mitstack-")
			dir := filepath.Join(admissionTestsDir, policy)
			files := fileNames(t, dir)
			failIf(t, !slices.Equal(files, []string{"accepted.yaml", "kyverno-test.yaml", "refused.yaml"}), "%s holds %v, want accepted.yaml, kyverno-test.yaml and refused.yaml", dir, files)

			test := admissionFixture(t, policy, "kyverno-test.yaml")

			assertPaths(t, policy+" kyverno-test.yaml", test, map[string]any{
				"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Test",
				"policies":  []any{"../../policies/" + policy + ".yaml"},
				"resources": []any{"accepted.yaml", "refused.yaml"},
			})
			results, ok := test["results"].([]any)
			fatalIf(t, !ok || len(results) != 2, "%s kyverno-test.yaml results = %#v, want one result for the accepted fixture and one for the refused", policy, test["results"])
			assertValues(t, policy+" accepted result", results[0].(map[string]any), map[string]any{
				"isValidatingPolicy": true, "policy": policy, "kind": "Deployment", "resources": []any{"accepted-" + short}, "result": "pass",
			})
			assertValues(t, policy+" refused result", results[1].(map[string]any), map[string]any{
				"isValidatingPolicy": true, "policy": policy, "kind": "Deployment", "resources": []any{"refused-" + short}, "result": "fail",
			})
			for file, name := range map[string]string{"accepted.yaml": "accepted-" + short, "refused.yaml": "refused-" + short} {
				doc := admissionFixture(t, policy, file)
				assertPaths(t, policy+" "+file, doc, map[string]any{
					"apiVersion": "apps/v1", "kind": "Deployment", "metadata.name": name, "metadata.namespace": admissionProbeNamespace,
				})
			}
		})
	}
}

func TestAdmission_DefaultDenyTestGeneratesThePolicyInAnAppNamespaceAndNamesASystemNamespaceAsRefused(t *testing.T) {
	dir := filepath.Join(admissionTestsDir, admissionGeneratorName)
	files := fileNames(t, dir)
	failIf(t, !slices.Equal(files, []string{"accepted.yaml", "generated-resource.yaml", "kyverno-test.yaml", "refused.yaml"}), "%s holds %v, want accepted.yaml, generated-resource.yaml, kyverno-test.yaml and refused.yaml", dir, files)

	test := admissionFixture(t, admissionGeneratorName, "kyverno-test.yaml")
	accepted := admissionFixture(t, admissionGeneratorName, "accepted.yaml")
	refused := admissionFixture(t, admissionGeneratorName, "refused.yaml")
	generated := admissionFixture(t, admissionGeneratorName, "generated-resource.yaml")

	assertPaths(t, "default-deny kyverno-test.yaml", test, map[string]any{
		"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Test",
		"policies":  []any{"../../policies/" + admissionGeneratorName + ".yaml"},
		"resources": []any{"accepted.yaml", "refused.yaml"},
	})
	results, ok := test["results"].([]any)
	fatalIf(t, !ok || len(results) != 1, "default-deny kyverno-test.yaml results = %#v, want the one pass for the app namespace: the Kyverno CLI reports no result for a namespace a matchCondition skips", test["results"])
	assertValues(t, "default-deny result", results[0].(map[string]any), map[string]any{
		"isGeneratingPolicy": true, "policy": admissionGeneratorName, "kind": "Namespace",
		"resources": []any{"accepted-generate-default-deny"}, "result": "pass", "generatedResource": "generated-resource.yaml",
	})
	assertPaths(t, "accepted.yaml", accepted, map[string]any{"kind": "Namespace", "metadata.name": "accepted-generate-default-deny"})
	failIf(t, !slices.Contains(admissionSystemNamespaces, dig(refused, "metadata", "name").(string)) || refused["kind"] != "Namespace", "refused.yaml = %v, want a system namespace from %v", refused, admissionSystemNamespaces)
	assertPaths(t, "generated-resource.yaml", generated, map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata.name": "mitstack-default-deny",
		"metadata.namespace": "accepted-generate-default-deny", "spec.podSelector": map[string]any{}, "spec.policyTypes": []any{"Ingress", "Egress"},
	})
	for _, rules := range []string{"ingress", "egress"} {
		_, set := dig(generated, "spec").(map[string]any)[rules]
		failIf(t, set, "generated-resource.yaml spec.%s is set, want a policy with no rule: a deny-all grants nothing", rules)
	}
}

func TestAdmission_EachPolicyAnnotationNamesOneOfTheThreeStandards(t *testing.T) {
	for _, name := range admissionPolicyNames {
		t.Run(name, func(t *testing.T) {
			policy := admissionPolicy(t, name)

			standard, _ := dig(policy, "metadata", "annotations", "mitstack.dev/standard").(string)

			named := slices.ContainsFunc(admissionStandards, func(s string) bool {
				rest, found := strings.CutPrefix(standard, s)
				return found && (rest == "" || strings.HasPrefix(rest, " ") && strings.TrimSpace(rest) != "")
			})
			failIf(t, !named, "%s mitstack.dev/standard = %q, want one of %q optionally followed by a space and the section", name, standard, admissionStandards)
		})
	}
}

func TestAdmission_EachPolicySkipsArgoCDsDryRunWhileItsCRDIsMissing(t *testing.T) {
	for _, name := range admissionPolicyNames {
		t.Run(name, func(t *testing.T) {
			got := dig(admissionPolicy(t, name), "metadata", "annotations", "argocd.argoproj.io/sync-options")

			failIf(t, got != admissionSyncOptions, "%s argocd.argoproj.io/sync-options = %#v, want %q, since the Kyverno CRDs exist only after Kyverno syncs", name, got, admissionSyncOptions)
		})
	}
}

func TestAdmission_ValidatingPoliciesDenyPodsAndEveryControllerThatCreatesThem(t *testing.T) {
	for _, name := range admissionValidatingPolicies {
		t.Run(name, func(t *testing.T) {
			policy := admissionPolicy(t, name)

			assertPaths(t, name, policy, map[string]any{
				"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy", "metadata.name": name,
				"spec.validationActions":                  []any{"Deny"},
				"spec.autogen.podControllers.controllers": stringList(admissionControllers),
			})
			rules, ok := dig(policy, "spec", "matchConstraints", "resourceRules").([]any)
			fatalIf(t, !ok || len(rules) != 1, "%s spec.matchConstraints.resourceRules = %#v, want one rule for pods", name, dig(policy, "spec", "matchConstraints", "resourceRules"))
			assertValues(t, name+" resource rule", rules[0].(map[string]any), map[string]any{
				"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE", "UPDATE"}, "resources": []any{"pods"},
			})
		})
	}
}

func TestAdmission_ValidatingPoliciesExcludeExactlyTheSystemNamespacesByName(t *testing.T) {
	for _, name := range admissionValidatingPolicies {
		t.Run(name, func(t *testing.T) {
			policy := admissionPolicy(t, name)

			got := dig(policy, "spec", "matchConstraints", "namespaceSelector", "matchExpressions")

			want := []any{map[string]any{"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": stringList(admissionSystemNamespaces)}}
			failIf(t, !equalValues(got, want), "%s spec.matchConstraints.namespaceSelector.matchExpressions = %#v, want %#v", name, got, want)
		})
	}
}

func TestAdmission_ValidationMessagesStartWithThePolicyName(t *testing.T) {
	for _, name := range admissionValidatingPolicies {
		t.Run(name, func(t *testing.T) {
			validations, ok := dig(admissionPolicy(t, name), "spec", "validations").([]any)
			fatalIf(t, !ok || len(validations) == 0, "%s spec.validations = %#v, want at least one validation", name, dig(admissionPolicy(t, name), "spec", "validations"))

			for i, v := range validations {
				message, _ := v.(map[string]any)["message"].(string)
				failIf(t, !strings.HasPrefix(message, name+": ") || strings.TrimPrefix(message, name+": ") == "", "%s validations[%d].message = %q, want it to start with %q and say why", name, i, message, name+": ")
			}
		})
	}
}

func TestAdmission_DefaultDenyPolicyGeneratesOnEveryNamespaceEventAndKeepsWhatItGenerated(t *testing.T) {
	policy := admissionPolicy(t, admissionGeneratorName)

	assertPaths(t, admissionGeneratorName, policy, map[string]any{
		"apiVersion": "policies.kyverno.io/v1", "kind": "GeneratingPolicy", "metadata.name": admissionGeneratorName,
		"spec.evaluation.synchronize.enabled":      true,
		"spec.evaluation.generateExisting.enabled": true,
	})
	rules, ok := dig(policy, "spec", "matchConstraints", "resourceRules").([]any)
	fatalIf(t, !ok || len(rules) != 1, "spec.matchConstraints.resourceRules = %#v, want one rule for namespaces", dig(policy, "spec", "matchConstraints", "resourceRules"))
	assertValues(t, "default-deny resource rule", rules[0].(map[string]any), map[string]any{
		"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE", "UPDATE"}, "resources": []any{"namespaces"},
	})
}

func TestAdmission_DefaultDenyPolicySkipsExactlyTheSystemNamespacesByName(t *testing.T) {
	conditions, ok := dig(admissionPolicy(t, admissionGeneratorName), "spec", "matchConditions").([]any)
	fatalIf(t, !ok || len(conditions) == 0, "spec.matchConditions = %#v, want a condition naming the system namespaces", dig(admissionPolicy(t, admissionGeneratorName), "spec", "matchConditions"))

	var quoted []string
	for _, c := range conditions {
		expression, _ := c.(map[string]any)["expression"].(string)
		for _, m := range quotedCEL.FindAllStringSubmatch(expression, -1) {
			quoted = append(quoted, m[1]+m[2])
		}
	}

	failIf(t, !slices.Equal(quoted, admissionSystemNamespaces), "spec.matchConditions name %q, want exactly %q in this order", quoted, admissionSystemNamespaces)
}

type podView struct {
	labels     map[string]any
	pod        map[string]any
	containers []map[string]any
}

func podOf(t *testing.T, what string, doc map[string]any) podView {
	t.Helper()
	v := podView{pod: dig(doc, "spec").(map[string]any), labels: map[string]any{}}
	if doc["kind"] == "Deployment" {
		v.pod = dig(doc, "spec", "template", "spec").(map[string]any)
		v.labels, _ = dig(doc, "spec", "template", "metadata", "labels").(map[string]any)
	} else {
		v.labels, _ = dig(doc, "metadata", "labels").(map[string]any)
	}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list, _ := v.pod[key].([]any)
		for _, c := range list {
			v.containers = append(v.containers, c.(map[string]any))
		}
	}
	fatalIf(t, len(v.containers) == 0, "%s declares no container", what)
	return v
}

// admissionChecks reports whether a pod complies with each Kyverno policy.
var admissionChecks = map[string]func(p podView) bool{
	"mitstack-require-app-label": func(p podView) bool {
		v, _ := p.labels["mitstack.dev/app"].(string)
		return v != ""
	},
	"mitstack-require-resource-limits": func(p podView) bool {
		return allContainers(p, func(c map[string]any) bool {
			limits, _ := dig(c, "resources", "limits").(map[string]any)
			return limits["cpu"] != nil && limits["memory"] != nil
		})
	},
	"mitstack-restrict-image-registries": func(p podView) bool {
		return allContainers(p, func(c map[string]any) bool {
			image, _ := c["image"].(string)
			return strings.HasPrefix(image, "ghcr.io/mitstack-eu/") || strings.HasPrefix(image, "839001574838.dkr.ecr.eu-central-1.amazonaws.com/")
		})
	},
	"mitstack-require-image-digest": func(p podView) bool {
		return allContainers(p, func(c map[string]any) bool {
			image, _ := c["image"].(string)
			return strings.Contains(image, "@sha256:")
		})
	},
	"mitstack-disallow-host-path": func(p podView) bool {
		volumes, _ := p.pod["volumes"].([]any)
		return !slices.ContainsFunc(volumes, func(v any) bool { _, host := v.(map[string]any)["hostPath"]; return host })
	},
}

func allContainers(p podView, ok func(c map[string]any) bool) bool {
	return !slices.ContainsFunc(p.containers, func(c map[string]any) bool { return !ok(c) })
}

func TestAdmission_AcceptedFixturesBreakNoPolicyAndRefusedFixturesBreakOnlyTheirOwn(t *testing.T) {
	for _, policy := range admissionValidatingPolicies {
		t.Run(policy, func(t *testing.T) {
			accepted := podOf(t, "accepted.yaml", admissionFixture(t, policy, "accepted.yaml"))
			refused := podOf(t, "refused.yaml", admissionFixture(t, policy, "refused.yaml"))

			for _, other := range admissionValidatingPolicies {
				failIf(t, !admissionChecks[other](accepted), "%s accepted.yaml breaks %s, want a fixture that complies with every policy", policy, other)
				complies := admissionChecks[other](refused)
				failIf(t, other == policy && complies, "%s refused.yaml complies with %s, want it to break that rule", policy, other)
				failIf(t, other != policy && !complies, "%s refused.yaml breaks %s as well, want it to break only its own rule, so a refusal names one policy", policy, other)
			}
		})
	}
}

func TestAdmission_DeploymentFixturesComplyWithPodSecurityRestrictedExceptWhereTheRuleUnderTestIsAVolume(t *testing.T) {
	for _, policy := range admissionValidatingPolicies {
		for _, file := range []string{"accepted.yaml", "refused.yaml"} {
			t.Run(policy+"/"+file, func(t *testing.T) {
				doc := admissionFixture(t, policy, file)
				p := podOf(t, file, doc)

				failIf(t, dig(p.pod, "securityContext", "runAsNonRoot") != true, "%s %s: pod securityContext.runAsNonRoot = %#v, want true", policy, file, dig(p.pod, "securityContext", "runAsNonRoot"))
				failIf(t, dig(p.pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault", "%s %s: pod seccompProfile.type = %#v, want RuntimeDefault", policy, file, dig(p.pod, "securityContext", "seccompProfile", "type"))
				for _, c := range p.containers {
					failIf(t, dig(c, "securityContext", "allowPrivilegeEscalation") != false, "%s %s: container %v allowPrivilegeEscalation = %#v, want false", policy, file, c["name"], dig(c, "securityContext", "allowPrivilegeEscalation"))
					failIf(t, !equalValues(dig(c, "securityContext", "capabilities", "drop"), []any{"ALL"}), "%s %s: container %v capabilities.drop = %#v, want [ALL]", policy, file, c["name"], dig(c, "securityContext", "capabilities", "drop"))
					failIf(t, dig(c, "securityContext", "privileged") == true, "%s %s: container %v is privileged, and only the probe may be", policy, file, c["name"])
				}
				matches := dig(doc, "spec", "selector", "matchLabels").(map[string]any)
				for k, v := range matches {
					failIf(t, p.labels[k] != v, "%s %s: selector label %s=%v is not on the pod template, which the API server refuses", policy, file, k, v)
				}
			})
		}
	}
}

func TestAdmission_PodSecurityProbeIsAPrivilegedPodThatBreaksNoKyvernoPolicy(t *testing.T) {
	doc := yamlMap(t, admissionProbeFile, admissionFile(t, admissionProbeFile))
	p := podOf(t, admissionProbeFile, doc)

	assertPaths(t, "the probe", doc, map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata.name": "pod-security-restricted", "metadata.namespace": admissionProbeNamespace})
	for _, policy := range admissionValidatingPolicies {
		failIf(t, !admissionChecks[policy](p), "the probe breaks %s, want Pod Security restricted to be the only control that refuses it", policy)
	}
	for _, c := range p.containers {
		failIf(t, dig(c, "securityContext", "privileged") != true, "container %v privileged = %#v, want true", c["name"], dig(c, "securityContext", "privileged"))
		failIf(t, dig(c, "securityContext", "allowPrivilegeEscalation") == false, "container %v sets allowPrivilegeEscalation false with privileged true, which the API server refuses before admission runs", c["name"])
	}
}

func stringList(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func equalValues(got, want any) bool { return reflect.DeepEqual(got, want) }

func TestAdmission_SignatureTestAdmitsThePinnedImageAndRefusesTheTwoFixturesWhichTheNodeAgentAlsoDryRuns(t *testing.T) {
	image := func(file string) any {
		return dig(admissionFixture(t, signaturePolicy, file), "spec", "containers").([]any)[0].(map[string]any)["image"]
	}
	refused, other := image("refused.yaml"), image("other-identity.yaml")

	failIf(t, image("accepted.yaml") != nodeAgentImage, "the admitted fixture runs %v, want the pinned %s, so the test proves the image a cluster runs", image("accepted.yaml"), nodeAgentImage)
	failIf(t, refused == nodeAgentImage || other == nodeAgentImage || refused == other, "the refused fixtures run %v and %v, want two digests apart from each other and from the pin", refused, other)
	results := admissionFixture(t, signaturePolicy, "kyverno-test.yaml")["results"].([]any)
	assertValues(t, "the admitted result", results[0].(map[string]any), map[string]any{"policy": signaturePolicy, "kind": "Pod", "resources": []any{"accepted-verify-node-agent-signature"}, "result": "pass"})
	assertValues(t, "the refused result", results[1].(map[string]any), map[string]any{"policy": signaturePolicy, "kind": "Pod",
		"resources": []any{"refused-verify-node-agent-signature", "other-identity-verify-node-agent-signature"}, "result": "fail"})
	fixtures := yamlMap(t, seedNodeAgentFixturesFile, renderGoldenSeed(t)[seedNodeAgentFixturesFile])
	assertValues(t, seedNodeAgentFixturesFile, fixtures, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "admission-fixtures", "namespace": "mitstack-node"},
		"data": map[string]any{
			signaturePolicy + "-unsigned":       admissionFile(t, admissionTestsDir, signaturePolicy, "refused.yaml"),
			signaturePolicy + "-other-identity": admissionFile(t, admissionTestsDir, signaturePolicy, "other-identity.yaml"),
		},
	})
}
