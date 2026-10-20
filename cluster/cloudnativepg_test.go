package cluster

// cloudnativepg_test.go pins the CloudNativePG operator every server's seed carries, the images its pods may run, and the network a database slice gets.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
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
			fatalIf(t, strings.Contains(rest, "/"), "the seed writes %s in a subdirectory of %s, want the component's files flat as cluster-bases holds them", p, dir)
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
		docs = append(docs, yamlDocs(t, wantCloudNativePGDir+"/"+name, files[name])...)
	}
	return docs
}

func pinnedImages(t *testing.T) []string {
	t.Helper()
	policy := admissionPolicy(t, "mitstack-restrict-image-registries")
	variables, _ := dig(policy, "spec", "variables").([]any)
	for _, v := range variables {
		if dig(v, "name") != "pinnedImages" {
			continue
		}
		expression, _ := dig(v, "expression").(string)
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
	fatalIf(t, len(deployments) != 1, "the cloudnative-pg component holds %d Deployments, want the operator's alone", len(deployments))
	containers, _ := dig(deployments[0], "spec", "template", "spec", "containers").([]any)
	fatalIf(t, len(containers) != 1, "the operator's Deployment runs %d containers, want one", len(containers))
	env := map[string]any{}
	for _, e := range dig(containers[0], "env").([]any) {
		env[dig(e, "name").(string)] = dig(e, "value")
	}

	failIf(t, dig(containers[0], "image") != wantOperatorImage, "the operator runs %v, want %s, the image pinnedImages names", dig(containers[0], "image"), wantOperatorImage)
	failIf(t, env["OPERATOR_IMAGE_NAME"] != wantOperatorImage, "OPERATOR_IMAGE_NAME = %v, want %s, the image each instance pod's bootstrap container runs", env["OPERATOR_IMAGE_NAME"], wantOperatorImage)
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

	failIf(t, !slices.Equal(images("instance.yaml"), []string{wantPostgres16Image, wantOperatorImage}), "instance.yaml runs %v, want Postgres on %s and the bootstrap container on %s", images("instance.yaml"), wantPostgres16Image, wantOperatorImage)
	failIf(t, !slices.Equal(images("tagged.yaml"), []string{untagged(wantPostgres16Image), untagged(wantOperatorImage)}), "tagged.yaml runs %v, want the pinned images named by tag alone", images("tagged.yaml"))
	failIf(t, slices.Contains(pinnedImages(t), images("unpinned.yaml")[0]), "unpinned.yaml runs %s, which pinnedImages names, want an image it refuses", images("unpinned.yaml")[0])
	failIf(t, dig(admissionFixture(t, "cloudnative-pg", "operator.yaml"), "metadata", "namespace") != "cnpg-system", "operator.yaml is not in cnpg-system")
	instanceNamespace := dig(admissionFixture(t, "cloudnative-pg", "instance.yaml"), "metadata", "namespace")
	selectors, _ := dig(admissionFixture(t, "cloudnative-pg", "values.yaml"), "namespaceSelector").([]any)
	inDatabaseSlice := slices.ContainsFunc(selectors, func(s any) bool {
		return dig(s, "name") == instanceNamespace && dig(s, "labels", "mitstack.dev/database-slice") == "true"
	})
	failIf(t, !inDatabaseSlice, "values.yaml does not label %v, instance.yaml's namespace, mitstack.dev/database-slice=true", instanceNamespace)
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
	fatalIf(t, selector == nil, "a rule names a nil selector")
	labels, _ := dig(selector, "matchLabels").(map[string]any)
	for k, v := range labels {
		if got, ok := e[k]; !ok || got != v {
			return false
		}
	}
	expressions, _ := dig(selector, "matchExpressions").([]any)
	for _, x := range expressions {
		key, _ := dig(x, "key").(string)
		_, has := e[key]
		switch dig(x, "operator") {
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			t.Fatalf("the policy uses matchExpressions operator %v, which this test does not evaluate", dig(x, "operator"))
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
	toPorts, _ := dig(rule, "toPorts").([]any)
	for _, tp := range toPorts {
		list, _ := dig(tp, "ports").([]any)
		for _, p := range list {
			ports = append(ports, fmt.Sprintf("%v/%v", dig(p, "port"), dig(p, "protocol")))
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
	fatalIf(t, !ok || len(specs) == 0, "the policy has no specs list")
	var got []string
	for _, spec := range specs {
		if !ep.selectedBy(t, dig(spec, "endpointSelector")) {
			continue
		}
		for direction, peers := range map[string]string{"egress": "toEndpoints", "ingress": "fromEndpoints"} {
			rules, _ := dig(spec, direction).([]any)
			for _, rule := range rules {
				ports := rulePorts(t, rule)
				entities, _ := dig(rule, "toEntities").([]any)
				for _, e := range entities {
					got = append(got, fmt.Sprintf("%s to entity %v on %s", direction, e, ports))
				}
				selectors, _ := dig(rule, peers).([]any)
				for _, s := range selectors {
					for _, peer := range slices.Sorted(maps.Keys(databaseSliceEndpoints)) {
						if databaseSliceEndpoints[peer].selectedBy(t, s) {
							got = append(got, fmt.Sprintf("%s with %s on %s", direction, peer, ports))
						}
					}
				}
				for _, key := range []string{"fromEntities", "toCIDR", "toCIDRSet", "fromCIDR", "fromCIDRSet", "toFQDNs", "toServices"} {
					failIf(t, dig(rule, key) != nil, "a %s rule uses %s, which this test does not evaluate", direction, key)
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
	fatalIf(t, !ok, "the seed writes no %s", wantDatabaseSlicesPolicy)
	policy := yamlMap(t, wantDatabaseSlicesPolicy, content)
	assertPaths(t, wantDatabaseSlicesPolicy, policy, map[string]any{
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

			failIf(t, !slices.Equal(got, tc.want), "the policy grants the %s pod %q, want exactly %q", tc.pod, got, tc.want)
		})
	}
}
