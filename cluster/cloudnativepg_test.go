package cluster

// cloudnativepg_test.go pins the CloudNativePG operator every server's seed carries, the images its pods may run, and the network a database slice gets.

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	wantCloudNativePGDir     = "cluster-bases/cloudnative-pg"
	wantDatabaseSlicesPolicy = "cluster/network-policy-mitstack-database-slices.yaml"

	// wantOperatorImage is the operator's image as its Deployment and OPERATOR_IMAGE_NAME name it, which an instance pod's bootstrap init container also runs.
	wantOperatorImage = "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1@sha256:923c267ec29636db3bee20f993d0ec4973fa22998e1adad37da79e4d32b5bc07"
	// wantPostgres16Image is what ghcr.io/cloudnative-pg/postgresql:16.15-system-trixie resolved to on 19 October 2026.
	wantPostgres16Image = "ghcr.io/cloudnative-pg/postgresql:16.15-system-trixie@sha256:8ca5699981c25db72e549e9fa69561bac233df15b9b1e3a6282847b0629bb5ea"
)

func filesUnder(t *testing.T, seed map[string]string, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for p, content := range seed {
		if rest, ok := strings.CutPrefix(p, dir+"/"); ok {
			testutil.FatalIf(t, strings.Contains(rest, "/"), "the seed writes %s in a subdirectory of %s, want the component's files flat as cluster-bases holds them", p, dir)
			files[rest] = content
		}
	}
	return files
}

func cloudNativePGDocs(t *testing.T) []map[string]any {
	t.Helper()
	files := filesUnder(t, renderGoldenSeedWithClusterBases(t), wantCloudNativePGDir)
	var docs []map[string]any
	for _, name := range slices.Sorted(maps.Keys(files)) {
		docs = append(docs, testutil.YamlDocs(t, wantCloudNativePGDir+"/"+name, files[name])...)
	}
	return docs
}

func pinnedImages(t *testing.T) []string {
	t.Helper()
	policy := admissionPolicy(t, "mitstack-restrict-image-registries")
	variables, _ := testutil.Dig(policy, "spec", "variables").([]any)
	for _, v := range variables {
		if testutil.Dig(v, "name") != "pinnedImages" {
			continue
		}
		expression, _ := testutil.Dig(v, "expression").(string)
		var images []string
		for _, m := range quotedCEL.FindAllStringSubmatch(expression, -1) {
			images = append(images, m[1]+m[2])
		}
		return images
	}
	t.Fatalf("mitstack-restrict-image-registries declares no pinnedImages variable")
	return nil
}

func TestSeed_TheCloudNativePGOperatorRunsThePinnedOperatorImage(t *testing.T) {
	var deployments []map[string]any
	for _, doc := range cloudNativePGDocs(t) {
		if doc["kind"] == "Deployment" {
			deployments = append(deployments, doc)
		}
	}
	testutil.FatalIf(t, len(deployments) != 1, "the cloudnative-pg component holds %d Deployments, want the operator's alone", len(deployments))
	containers, _ := testutil.Dig(deployments[0], "spec", "template", "spec", "containers").([]any)
	testutil.FatalIf(t, len(containers) != 1, "the operator's Deployment runs %d containers, want one", len(containers))
	env := map[string]any{}
	for _, e := range testutil.Dig(containers[0], "env").([]any) {
		env[testutil.Dig(e, "name").(string)] = testutil.Dig(e, "value")
	}

	testutil.FailIf(t, testutil.Dig(containers[0], "image") != wantOperatorImage, "the operator runs %v, want %s, the image pinnedImages names", testutil.Dig(containers[0], "image"), wantOperatorImage)
	testutil.FailIf(t, env["OPERATOR_IMAGE_NAME"] != wantOperatorImage, "OPERATOR_IMAGE_NAME = %v, want %s, the image each instance pod's bootstrap container runs", env["OPERATOR_IMAGE_NAME"], wantOperatorImage)
}

func TestAdmission_CloudNativePGTestRunsThePinnedImagesInADatabaseSliceAndTheSameImagesByTag(t *testing.T) {
	images := func(file string) []string {
		var got []string
		for _, c := range podOf(t, file, admissionFixture(t, "cloudnative-pg", file)).containers {
			got = append(got, c["image"].(string))
		}
		return got
	}
	untagged := func(image string) string { name, _, _ := strings.Cut(image, "@"); return name }

	testutil.FailIf(t, !slices.Equal(images("instance.yaml"), []string{wantPostgres16Image, wantOperatorImage}), "instance.yaml runs %v, want Postgres on %s and the bootstrap container on %s", images("instance.yaml"), wantPostgres16Image, wantOperatorImage)
	testutil.FailIf(t, !slices.Equal(images("tagged.yaml"), []string{untagged(wantPostgres16Image), untagged(wantOperatorImage)}), "tagged.yaml runs %v, want the pinned images named by tag alone", images("tagged.yaml"))
	testutil.FailIf(t, slices.Contains(pinnedImages(t), images("unpinned.yaml")[0]), "unpinned.yaml runs %s, which pinnedImages names, want an image it refuses", images("unpinned.yaml")[0])
	testutil.FailIf(t, testutil.Dig(admissionFixture(t, "cloudnative-pg", "operator.yaml"), "metadata", "namespace") != "cnpg-system", "operator.yaml is not in cnpg-system")
	instanceNamespace := testutil.Dig(admissionFixture(t, "cloudnative-pg", "instance.yaml"), "metadata", "namespace")
	selectors, _ := testutil.Dig(admissionFixture(t, "cloudnative-pg", "values.yaml"), "namespaceSelector").([]any)
	inDatabaseSlice := slices.ContainsFunc(selectors, func(s any) bool {
		return testutil.Dig(s, "name") == instanceNamespace && testutil.Dig(s, "labels", "mitstack.dev/database-slice") == "true"
	})
	testutil.FailIf(t, !inDatabaseSlice, "values.yaml does not label %v, instance.yaml's namespace, mitstack.dev/database-slice=true", instanceNamespace)
}

// ciliumEndpoint is a pod as Cilium labels it: its own labels under k8s:, its namespace's under io.cilium.k8s.namespace.labels.
type ciliumEndpoint map[string]string

func endpoint(namespace string, namespaceLabels, podLabels map[string]string) ciliumEndpoint {
	e := ciliumEndpoint{"k8s:io.kubernetes.pod.namespace": namespace}
	for k, v := range namespaceLabels {
		e["k8s:io.cilium.k8s.namespace.labels."+k] = v
	}
	for k, v := range podLabels {
		e["k8s:"+k] = v
	}
	return e
}

func (e ciliumEndpoint) selectedBy(t *testing.T, selector any) bool {
	t.Helper()
	testutil.FatalIf(t, selector == nil, "a rule names a nil selector")
	labels, _ := testutil.Dig(selector, "matchLabels").(map[string]any)
	for k, v := range labels {
		if got, ok := e[k]; !ok || got != v {
			return false
		}
	}
	expressions, _ := testutil.Dig(selector, "matchExpressions").([]any)
	for _, x := range expressions {
		key, _ := testutil.Dig(x, "key").(string)
		_, has := e[key]
		switch testutil.Dig(x, "operator") {
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			t.Fatalf("the policy uses matchExpressions operator %v, which this test does not evaluate", testutil.Dig(x, "operator"))
		}
	}
	return true
}

var databaseSliceEndpoints = map[string]ciliumEndpoint{
	"instance": endpoint("app-s4338-pg", map[string]string{"mitstack.dev/database-slice": "true", "mitstack.dev/subscription": "sub-pg"},
		map[string]string{"cnpg.io/cluster": "shared", "cnpg.io/podRole": "instance", "mitstack.dev/app": "postgres"}),
	"job": endpoint("app-s4338-pg", map[string]string{"mitstack.dev/database-slice": "true", "mitstack.dev/subscription": "sub-pg"},
		map[string]string{"cnpg.io/cluster": "shared", "cnpg.io/jobRole": "initdb", "mitstack.dev/app": "postgres"}),
	"app": endpoint("app-s4338-a1", map[string]string{"mitstack.dev/subscription": "sub-a1"}, map[string]string{"mitstack.dev/app": "shop"}),
	"instance outside a database slice": endpoint("app-s4338-b2", map[string]string{"mitstack.dev/subscription": "sub-b2"},
		map[string]string{"cnpg.io/cluster": "own", "cnpg.io/podRole": "instance", "mitstack.dev/app": "own"}),
	"operator": endpoint("cnpg-system", map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
		map[string]string{"app.kubernetes.io/name": "cloudnative-pg", "app.kubernetes.io/instance": "cloudnative-pg", "mitstack.dev/app": "cloudnative-pg"}),
	"system pod": endpoint("kube-system", nil, map[string]string{"k8s-app": "kube-dns"}),
}

func rulePorts(t *testing.T, rule any) string {
	t.Helper()
	var ports []string
	toPorts, _ := testutil.Dig(rule, "toPorts").([]any)
	for _, tp := range toPorts {
		list, _ := testutil.Dig(tp, "ports").([]any)
		for _, p := range list {
			ports = append(ports, fmt.Sprintf("%v/%v", testutil.Dig(p, "port"), testutil.Dig(p, "protocol")))
		}
	}
	if len(ports) == 0 {
		return "any port"
	}
	return strings.Join(ports, ",")
}

// grants lists what the policy allows the endpoint named, as "egress to <peer> on <ports>" and "ingress from <peer> on <ports>".
func grants(t *testing.T, policy map[string]any, name string) []string {
	t.Helper()
	ep := databaseSliceEndpoints[name]
	specs, ok := policy["specs"].([]any)
	testutil.FatalIf(t, !ok || len(specs) == 0, "the policy has no specs list")
	var got []string
	for _, spec := range specs {
		if !ep.selectedBy(t, testutil.Dig(spec, "endpointSelector")) {
			continue
		}
		for direction, peers := range map[string]string{"egress": "toEndpoints", "ingress": "fromEndpoints"} {
			rules, _ := testutil.Dig(spec, direction).([]any)
			for _, rule := range rules {
				ports := rulePorts(t, rule)
				entities, _ := testutil.Dig(rule, "toEntities").([]any)
				for _, e := range entities {
					got = append(got, fmt.Sprintf("%s to entity %v on %s", direction, e, ports))
				}
				selectors, _ := testutil.Dig(rule, peers).([]any)
				for _, s := range selectors {
					for _, peer := range slices.Sorted(maps.Keys(databaseSliceEndpoints)) {
						if databaseSliceEndpoints[peer].selectedBy(t, s) {
							got = append(got, fmt.Sprintf("%s with %s on %s", direction, peer, ports))
						}
					}
				}
				for _, key := range []string{"fromEntities", "toCIDR", "toCIDRSet", "fromCIDR", "fromCIDRSet", "toFQDNs", "toServices"} {
					testutil.FailIf(t, testutil.Dig(rule, key) != nil, "a %s rule uses %s, which this test does not evaluate", direction, key)
				}
			}
		}
	}
	slices.Sort(got)
	return slices.Compact(got)
}

func databaseSlicesPolicyIn(t *testing.T, seed map[string]string) map[string]any {
	t.Helper()
	content, ok := seed[wantDatabaseSlicesPolicy]
	testutil.FatalIf(t, !ok, "the seed writes no %s", wantDatabaseSlicesPolicy)
	policy := testutil.YamlMap(t, wantDatabaseSlicesPolicy, content)
	testutil.AssertPaths(t, wantDatabaseSlicesPolicy, policy, map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumClusterwideNetworkPolicy", "metadata.name": "mitstack-database-slices",
	})
	return policy
}

func TestDatabaseSlicesPolicy_GrantsEachPodExactlyItsAllows(t *testing.T) {
	policy := databaseSlicesPolicyIn(t, renderGoldenSeed(t))
	for _, tc := range []struct {
		name, pod string
		want      []string
	}{
		{"a Postgres instance reaches the API server and the other instances, and admits the operator on 8000 and every slice on 5432", "instance", []string{
			"egress to entity kube-apiserver on any port",
			"egress with instance on 5432/TCP",
			"ingress with app on 5432/TCP",
			"ingress with instance on 5432/TCP",
			"ingress with instance outside a database slice on 5432/TCP",
			"ingress with job on 5432/TCP",
			"ingress with operator on 8000/TCP",
		}},
		{"a CloudNativePG Job reaches the API server and the instances on 5432", "job", []string{
			"egress to entity kube-apiserver on any port",
			"egress with instance on 5432/TCP",
		}},
		{"a pod in an app slice reaches only the database slice's instances, on 5432", "app", []string{
			"egress with instance on 5432/TCP",
		}},
		{"a pod outside a database slice gains none of the database slice's allows", "instance outside a database slice", []string{
			"egress with instance on 5432/TCP",
		}},
		{"the operator in cnpg-system is selected by no rule, as no other system namespace is", "operator", nil},
		{"a system pod is selected by no rule", "system pod", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := grants(t, policy, tc.pod)

			testutil.FailIf(t, !slices.Equal(got, tc.want), "the policy grants the %s pod %q, want exactly %q", tc.pod, got, tc.want)
		})
	}
}

const (
	// wantCloudNativePGTree is what `git rev-parse v0.5.0:cloudnative-pg` answers in mitstack-eu/cluster-bases.
	wantCloudNativePGTree        = "761b32a055880d3840d5500a49b80205d30f1877"
	wantCloudNativePGApplication = "cluster/cloudnative-pg.yaml"
)

func cloudSeed(t *testing.T) map[string]string {
	t.Helper()
	seed, err := RenderSeed(PinnedVersions, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)
	return seed
}

func dedicatedSeed(t *testing.T) map[string]string {
	t.Helper()
	seed, err := RenderDedicatedSeed(PinnedVersions, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderDedicatedSeed: %v", err)
	return seed
}

// everyServerSeed is the repository a Cloud and a dedicated server each receive.
func everyServerSeed(t *testing.T) map[string]func(t *testing.T) map[string]string {
	t.Helper()
	return map[string]func(t *testing.T) map[string]string{"a Cloud server": cloudSeed, "a dedicated server": dedicatedSeed}
}

func TestSeed_EveryServersRepositoryCarriesCloudNativePGAsTheClusterBasesReleaseHoldsIt(t *testing.T) {
	for server, seed := range everyServerSeed(t) {
		t.Run(server, func(t *testing.T) {
			files := filesUnder(t, seed(t), wantCloudNativePGDir)

			testutil.FatalIf(t, len(files) == 0, "%s's seed writes nothing under %s/, want cluster-bases %s's cloudnative-pg directory", server, wantCloudNativePGDir, wantClusterBasesTag)
			got := gitTreeID(files)
			testutil.FailIf(t, got != wantCloudNativePGTree, "the seed's %s/ is git tree %s holding %v, want %s, the tree of cloudnative-pg at cluster-bases %s", wantCloudNativePGDir, got, slices.Sorted(maps.Keys(files)), wantCloudNativePGTree, wantClusterBasesTag)
		})
	}
}

func TestSeed_EveryServersRepositorySyncsCloudNativePGIntoCnpgSystemInTheCRDWave(t *testing.T) {
	for server, seed := range everyServerSeed(t) {
		t.Run(server, func(t *testing.T) {
			content, ok := seed(t)[wantCloudNativePGApplication]
			testutil.FatalIf(t, !ok, "%s's seed writes no %s", server, wantCloudNativePGApplication)

			app := testutil.YamlMap(t, wantCloudNativePGApplication, content)

			testutil.AssertPaths(t, wantCloudNativePGApplication, app, map[string]any{
				"kind":               "Application",
				"metadata.name":      "cloudnative-pg",
				"metadata.namespace": "argocd",
				"metadata.annotations": map[string]any{
					"argocd.argoproj.io/sync-wave":   "-1",
					"mitstack.dev/cluster-bases-tag": wantClusterBasesTag,
				},
				"spec.source.repoURL":                      testutil.FixtureRepoURL,
				"spec.source.path":                         wantCloudNativePGDir,
				"spec.source.targetRevision":               "HEAD",
				"spec.destination.server":                  "https://kubernetes.default.svc",
				"spec.destination.namespace":               "cnpg-system",
				"spec.syncPolicy.automated.prune":          true,
				"spec.syncPolicy.automated.selfHeal":       true,
				"spec.syncPolicy.syncOptions":              []any{"ServerSideApply=true"},
				"spec.ignoreDifferences":                   nil,
				"spec.syncPolicy.managedNamespaceMetadata": nil,
			})
		})
	}
}

func TestDatabaseSlicesPolicy_EveryServersRepositoryCarriesIt(t *testing.T) {
	for server, seed := range everyServerSeed(t) {
		t.Run(server, func(t *testing.T) {
			files := seed(t)
			databaseSlicesPolicyIn(t, files)

			testutil.AssertSameBytes(t, server+"'s "+wantDatabaseSlicesPolicy, files[wantDatabaseSlicesPolicy], testutil.ReadGolden(t, filepath.Join(goldenSeedDir(), filepath.Base(wantDatabaseSlicesPolicy))))
		})
	}
}
