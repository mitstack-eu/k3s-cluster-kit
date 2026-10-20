package cluster

// clusterseed_test.go renders the cluster repository seed: the Argo CD Applications, issuer, upgrade plan and notifications it carries.

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
	"go.yaml.in/yaml/v3"
)

const (
	seedCertManagerPath   = "cluster/cert-manager.yaml"
	seedClusterIssuerPath = "cluster/cluster-issuer.yaml"
	inClusterAPI          = "https://kubernetes.default.svc"

	gitOpsNotificationsURL = "https://api.mitstack.dev/v1/gitops-notifications"
)

var seedAppNames = map[string]string{testutil.SeedArgoCDPath: "argocd", testutil.SeedCiliumPath: "cilium"}

func eachVersions(t *testing.T, check func(t *testing.T, v Versions)) {
	for label, v := range map[string]Versions{"the pinned versions": PinnedVersions, "other versions": nonDefaultVersions(t)} {
		t.Run(label, func(t *testing.T) { check(t, v) })
	}
}

const stubACMESolverDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func recordACMESolverDigest(t *testing.T, version string) {
	t.Helper()
	acmesolverDigests[version] = stubACMESolverDigest
	t.Cleanup(func() { delete(acmesolverDigests, version) })
}

const stubUpgradeControllerDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func recordUpgradeControllerDigest(t *testing.T, version string) {
	t.Helper()
	upgradeControllerDigests[version] = stubUpgradeControllerDigest
	t.Cleanup(func() { delete(upgradeControllerDigests, version) })
}

func nonDefaultVersions(t *testing.T) Versions {
	v := PinnedVersions
	v.CiliumVersion = "1.19.9"
	v.ArgoCDChartVersion = "10.9.9"
	v.K3sVersion = "v1.37.1+k3s1"
	v.KuredChartVersion = "6.1.9"
	v.SystemUpgradeControllerVersion = "v0.20.9"
	recordUpgradeControllerDigest(t, v.SystemUpgradeControllerVersion)
	v.TraefikChartVersion = "41.6.9"
	v.CertManagerChartVersion = "v1.21.9"
	recordACMESolverDigest(t, v.CertManagerChartVersion)
	setKyvernoVersion(&v, "3.9.9")
	return v
}

func seedFiles(t *testing.T, v Versions) map[string]string {
	t.Helper()
	files, err := RenderSeed(v, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)
	paths := slices.Sorted(maps.Keys(files))
	testutil.FatalIf(t, !slices.Equal(paths, testutil.WantSeedPaths), "RenderSeed renders %v, want exactly %v", paths, testutil.WantSeedPaths)
	return files
}

func seedDoc(t *testing.T, v Versions, path string) map[string]any {
	t.Helper()
	return testutil.YamlMap(t, path, seedFiles(t, v)[path])
}

func bootstrapHelmCharts(t *testing.T, v Versions) map[string]map[string]any {
	t.Helper()
	in := fixtureRenderInputs()
	in.Versions = v
	ud := renderOK(t, in)
	charts := map[string]map[string]any{}
	for _, f := range testutil.ParseUserData(t, ud).WriteFiles {
		if !strings.HasPrefix(f.Path, manifestsDir+"/") || !strings.HasSuffix(f.Path, ".yaml") {
			continue
		}
		for _, doc := range testutil.YamlDocs(t, f.Path, f.Content) {
			if doc["kind"] != "HelmChart" {
				continue
			}
			name, _ := testutil.Dig(doc, "metadata", "name").(string)
			_, dup := charts[name]
			testutil.FatalIf(t, dup, "the user data carries two HelmCharts named %q", name)
			charts[name] = doc
		}
	}
	for _, name := range []string{"argocd", "cilium"} {
		testutil.FatalIf(t, charts[name] == nil, "the user data carries no HelmChart named %s among the boot manifests", name)
	}
	return charts
}

func seedApplications(t *testing.T, v Versions) map[string]map[string]any {
	t.Helper()
	files := seedFiles(t, v)
	apps := map[string]map[string]any{}
	for path, name := range seedAppNames {
		apps[name] = testutil.YamlMap(t, path, files[path])
	}
	return apps
}

func TestRenderSeed_IsOneArgoCDApplicationPerFileForArgoCDAndCilium(t *testing.T) {
	for name, app := range seedApplications(t, PinnedVersions) {
		testutil.AssertPaths(t, name+" Application", app, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata.name": name, "metadata.namespace": "argocd",
			"spec.project": "default", "spec.destination.server": inClusterAPI,
		})
		assertNoCredentialDeclared(t, name+" Application", app)
	}
}

var ignoreDifferenceKeys = []string{"group", "jsonPointers", "kind", "name", "namespace"}

func assertNoCredentialDeclared(t *testing.T, what string, app map[string]any) {
	t.Helper()
	walked := maps.Clone(app)
	spec, _ := app["spec"].(map[string]any)
	var references []any
	if spec != nil {
		specCopy := maps.Clone(spec)
		if raw, ok := specCopy["ignoreDifferences"]; ok {
			list, isList := raw.([]any)
			testutil.FatalIf(t, !isList, "%s spec.ignoreDifferences is %T, want a list", what, raw)
			references = list
			delete(specCopy, "ignoreDifferences")
		}
		walked["spec"] = specCopy
	}
	assertNoCredentialKeys(t, what, walked)
	for i, entry := range references {
		e, ok := entry.(map[string]any)
		if !ok {
			t.Errorf("%s spec.ignoreDifferences[%d] is %T, want a mapping", what, i, entry)
			continue
		}
		keys := slices.Sorted(maps.Keys(e))
		testutil.FailIf(t, !slices.Equal(keys, ignoreDifferenceKeys), "%s spec.ignoreDifferences[%d] has keys %v, want exactly %v", what, i, keys, ignoreDifferenceKeys)
	}
}

func TestRenderSeed_EachSourceIsTheBootstrapHelmChartItAdopts(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		charts := bootstrapHelmCharts(t, v)
		apps := seedApplications(t, v)
		for _, name := range []string{"argocd", "cilium"} {
			chart, app := charts[name], apps[name]
			what := name + " Application against the " + name + " HelmChart"
			testutil.AssertPaths(t, what, app, map[string]any{
				"spec.source.repoURL": testutil.Dig(chart, "spec", "repo"), "spec.source.chart": testutil.Dig(chart, "spec", "chart"),
				"spec.source.targetRevision": testutil.Dig(chart, "spec", "version"), "spec.source.helm.releaseName": testutil.Dig(chart, "metadata", "name"),
				"spec.destination.namespace": testutil.Dig(chart, "spec", "targetNamespace"),
			})
			values, ok := testutil.Dig(app, "spec", "source", "helm", "values").(string)
			if !ok {
				t.Errorf("%s: spec.source.helm.values is %T, want the values text", what, testutil.Dig(app, "spec", "source", "helm", "values"))
				continue
			}
			want, _ := testutil.Dig(chart, "spec", "valuesContent").(string)
			testutil.FailIf(t, values != want, "%s: helm.values differ from the HelmChart's valuesContent\n got %q\nwant %q", what, values, want)
		}
		// The HelmCharts follow v, so the comparison above is over v.
		got := testutil.Dig(charts["cilium"], "spec", "version")
		testutil.FatalIf(t, got != v.CiliumVersion, "the cilium HelmChart version is %v, want %s", got, v.CiliumVersion)
		got2 := testutil.Dig(charts["argocd"], "spec", "version")
		testutil.FatalIf(t, got2 != v.ArgoCDChartVersion, "the argocd HelmChart version is %v, want %s", got2, v.ArgoCDChartVersion)
	})
}

func TestRenderSeed_CiliumRunsOneOperatorThatRollsInPlace(t *testing.T) {
	app := seedApplications(t, PinnedVersions)["cilium"]
	values, ok := testutil.Dig(app, "spec", "source", "helm", "values").(string)
	testutil.FatalIf(t, !ok, "cilium Application spec.source.helm.values is %T, want a string of YAML", testutil.Dig(app, "spec", "source", "helm", "values"))
	assertOneOperatorRollingInPlace(t, "cilium Application helm.values", testutil.YamlMap(t, "cilium helm.values", values))
}

func TestRenderSeed_BothApplicationsPruneAndSelfHeal(t *testing.T) {
	for name, app := range seedApplications(t, PinnedVersions) {
		automated, ok := testutil.Dig(app, "spec", "syncPolicy", "automated").(map[string]any)
		if !ok {
			t.Errorf("%s Application spec.syncPolicy.automated is %T, want a mapping", name, testutil.Dig(app, "spec", "syncPolicy", "automated"))
			continue
		}
		testutil.FailIf(t, automated["prune"] != true || automated["selfHeal"] != true, "%s Application syncPolicy.automated = %v, want prune: true and selfHeal: true", name, automated)
	}
}

func TestRenderSeed_ArgoCDSyncsServerSide(t *testing.T) {
	app := seedApplications(t, PinnedVersions)["argocd"]
	opts := stringsOf(t, "argocd syncPolicy.syncOptions", testutil.Dig(app, "spec", "syncPolicy", "syncOptions"))
	if !slices.Contains(opts, "ServerSideApply=true") {
		t.Errorf("argocd Application syncOptions = %q, want ServerSideApply=true among them", opts)
	}
}

var ciliumNonIdempotentSecrets = map[string][]string{
	"cilium-ca":                 {"/data/ca.crt", "/data/ca.key"},
	"hubble-relay-client-certs": {"/data/ca.crt", "/data/tls.crt", "/data/tls.key"},
	"hubble-server-certs":       {"/data/ca.crt", "/data/tls.crt", "/data/tls.key"},
}

func TestRenderSeed_CiliumIgnoresExactlyTheRegeneratedCertificateSecrets(t *testing.T) {
	app := seedApplications(t, PinnedVersions)["cilium"]
	raw, ok := testutil.Dig(app, "spec", "ignoreDifferences").([]any)
	testutil.FatalIf(t, !ok, "cilium Application spec.ignoreDifferences is %T, want a list", testutil.Dig(app, "spec", "ignoreDifferences"))
	got := map[string][]string{}
	for i, entry := range raw {
		e, ok := entry.(map[string]any)
		testutil.FatalIf(t, !ok, "ignoreDifferences[%d] is %T, want a mapping", i, entry)
		name, _ := e["name"].(string)
		what := fmt.Sprintf("ignoreDifferences[%d] (%s)", i, name)
		pointers := stringsOf(t, what+" jsonPointers", e["jsonPointers"])
		slices.Sort(pointers)
		testutil.AssertValues(t, what, e, map[string]any{
			"group": "", "kind": "Secret", "name": name, "namespace": "kube-system", "jsonPointers": e["jsonPointers"],
		})
		_, dup := got[name]
		testutil.FailIf(t, dup, "ignoreDifferences names %s twice", name)
		got[name] = pointers
	}
	testutil.FailIf(t, !reflect.DeepEqual(got, ciliumNonIdempotentSecrets), "ignoreDifferences covers %v, want exactly %v", got, ciliumNonIdempotentSecrets)
	opts := stringsOf(t, "cilium syncPolicy.syncOptions", testutil.Dig(app, "spec", "syncPolicy", "syncOptions"))
	if !slices.Contains(opts, "RespectIgnoreDifferences=true") {
		t.Errorf("cilium Application syncOptions = %q, want RespectIgnoreDifferences=true among them, so a sync leaves the ignored fields as the cluster has them", opts)
	}
}

func TestRenderSeed_IsDeterministic(t *testing.T) {
	first, err := RenderSeed(PinnedVersions, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)
	second, err := RenderSeed(PinnedVersions, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)
	testutil.FailIf(t, !reflect.DeepEqual(first, second), "two renders of the same versions differ")
}

func automatedPruneSelfHeal(t *testing.T, what string, app map[string]any) {
	t.Helper()
	automated, ok := testutil.Dig(app, "spec", "syncPolicy", "automated").(map[string]any)
	testutil.FailIf(t, !ok || automated["prune"] != true || automated["selfHeal"] != true, "%s spec.syncPolicy.automated = %#v, want prune: true and selfHeal: true", what, testutil.Dig(app, "spec", "syncPolicy", "automated"))
}

func TestRenderSeed_KuredRebootsOnlyBetween0200And0300UTC(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := seedDoc(t, v, testutil.SeedKuredPath)
		testutil.AssertPaths(t, "kured Application", app, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata.name": "kured", "metadata.namespace": "argocd",
			"spec.project": "default", "spec.source.repoURL": "https://kubereboot.github.io/charts", "spec.source.chart": "kured",
			"spec.source.targetRevision": v.KuredChartVersion, "spec.source.helm.releaseName": "kured",
			"spec.destination": map[string]any{"server": inClusterAPI, "namespace": "kube-system"},
		})
		automatedPruneSelfHeal(t, "kured Application", app)
		assertNoCredentialDeclared(t, "kured Application", app)

		values, ok := testutil.Dig(app, "spec", "source", "helm", "values").(string)
		testutil.FatalIf(t, !ok, "kured Application spec.source.helm.values is %T, want the values text", testutil.Dig(app, "spec", "source", "helm", "values"))
		configuration, ok := testutil.Dig(testutil.YamlMap(t, "kured helm.values", values), "configuration").(map[string]any)
		testutil.FatalIf(t, !ok, "kured helm.values carries no configuration mapping:\n%s", values)
		// A drain a PodDisruptionBudget blocks gives up after 15 minutes
		// and the reboot goes ahead, so kured never leaves the node
		// cordoned.
		testutil.AssertValues(t, "kured configuration", configuration, map[string]any{
			"startTime":      "02:00",
			"endTime":        "03:00",
			"timeZone":       "UTC",
			"period":         "5m",
			"rebootSentinel": "/var/run/reboot-required",
			"drainTimeout":   "15m",
			"forceReboot":    true,
		})
	})
}

func TestRenderSeed_SystemUpgradeControllerRunsThePinnedReleaseByItsDigest(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := seedDoc(t, v, testutil.SeedUpgradeControllerPath)
		testutil.AssertPaths(t, "system-upgrade-controller Application", app, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata.name": "system-upgrade-controller", "metadata.namespace": "argocd",
			"spec.project": "default", "spec.destination": map[string]any{"server": inClusterAPI, "namespace": "system-upgrade"},
		})
		source, ok := testutil.Dig(app, "spec", "source").(map[string]any)
		testutil.FatalIf(t, !ok, "system-upgrade-controller spec.source is %T, want a mapping", testutil.Dig(app, "spec", "source"))
		testutil.AssertValues(t, "system-upgrade-controller source", source, map[string]any{
			"repoURL":        "https://github.com/rancher/system-upgrade-controller",
			"targetRevision": v.SystemUpgradeControllerVersion,
			"path":           ".",
			"kustomize": map[string]any{
				"images": []any{"rancher/system-upgrade-controller:" + v.SystemUpgradeControllerVersion + "@" + upgradeControllerDigests[v.SystemUpgradeControllerVersion]},
			},
		})
		automatedPruneSelfHeal(t, "system-upgrade-controller Application", app)
		assertNoCredentialDeclared(t, "system-upgrade-controller Application", app)
	})
}

// upgradeControllerPinnedDigest is the image index Docker Hub serves for rancher/system-upgrade-controller:v0.20.2.
const upgradeControllerPinnedDigest = "sha256:61b68d4372baf7ae90fb0f879feea1c082381a8b7547cc5ec85d393c497b11cb"

func TestRenderSeed_SystemUpgradeControllerDigestIsRecordedForThePinnedRelease(t *testing.T) {
	got := upgradeControllerDigests[PinnedVersions.SystemUpgradeControllerVersion]

	testutil.FailIf(t, got != upgradeControllerPinnedDigest, "upgradeControllerDigests[%q] = %q; want %q", PinnedVersions.SystemUpgradeControllerVersion, got, upgradeControllerPinnedDigest)
}

func TestRenderSeed_RefusesASystemUpgradeControllerVersionWithNoRecordedDigest(t *testing.T) {
	v := PinnedVersions
	v.SystemUpgradeControllerVersion = "v0.20.3"

	files, err := RenderSeed(v, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)

	testutil.FatalIf(t, err == nil, "RenderSeed with SystemUpgradeControllerVersion %q rendered %d files; want an error naming the missing system-upgrade-controller digest", v.SystemUpgradeControllerVersion, len(files))
	testutil.FailIf(t, !strings.Contains(err.Error(), "system-upgrade-controller digest") || !strings.Contains(err.Error(), "v0.20.3"), "RenderSeed with SystemUpgradeControllerVersion %q = %q; want an error naming the system-upgrade-controller digest and the version", v.SystemUpgradeControllerVersion, err)
}

func TestRenderSeed_K3sUpgradePlanFollowsThePinnedMinorsChannelInsideTheWindow(t *testing.T) {
	for _, tc := range []struct {
		k3s, channel string
	}{
		{"v1.36.3+k3s1", "v1.36"},
		{"v1.37.1+k3s1", "v1.37"},
		{"v1.36.6-rc1+k3s1", "v1.36"},
		{"v1.40.12+k3s2", "v1.40"},
	} {
		t.Run(tc.k3s, func(t *testing.T) {
			v := PinnedVersions
			v.K3sVersion = tc.k3s
			plan := seedDoc(t, v, testutil.SeedK3sUpgradePlanPath)
			testutil.AssertValues(t, "k3s upgrade Plan", map[string]any{
				"apiVersion": plan["apiVersion"], "kind": plan["kind"],
				"name": testutil.Dig(plan, "metadata", "name"), "namespace": testutil.Dig(plan, "metadata", "namespace"),
				"syncOptions": testutil.Dig(plan, "metadata", "annotations", "argocd.argoproj.io/sync-options"),
			}, map[string]any{
				"apiVersion": "upgrade.cattle.io/v1", "kind": "Plan",
				"name": "k3s-server", "namespace": "system-upgrade",
				"syncOptions": "SkipDryRunOnMissingResource=true",
			})
			spec, ok := plan["spec"].(map[string]any)
			testutil.FatalIf(t, !ok, "the k3s upgrade Plan's spec is %T, want a mapping", plan["spec"])
			window, ok := spec["window"].(map[string]any)
			testutil.FatalIf(t, !ok, "the k3s upgrade Plan's spec.window is %#v, want a mapping", spec["window"])
			withoutWindow := maps.Clone(spec)
			delete(withoutWindow, "window")
			testutil.AssertValues(t, "k3s upgrade Plan spec", withoutWindow, map[string]any{
				"concurrency": 1,
				"cordon":      true,
				"nodeSelector": map[string]any{"matchExpressions": []any{
					map[string]any{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists"},
				}},
				"serviceAccountName": "system-upgrade",
				"upgrade":            map[string]any{"image": "rancher/k3s-upgrade"},
				"channel":            "https://update.k3s.io/v1-release/channels/" + tc.channel,
			})
			days := stringsOf(t, "spec.window.days", window["days"])
			slices.Sort(days)
			want := []string{"friday", "monday", "saturday", "sunday", "thursday", "tuesday", "wednesday"}
			testutil.FailIf(t, !slices.Equal(days, want), "spec.window.days = %q, want every day of the week, %q", days, want)
			delete(window, "days")
			testutil.AssertValues(t, "k3s upgrade Plan spec.window", window, map[string]any{
				"startTime": "03:00", "endTime": "05:00", "timeZone": "UTC",
			})
			assertNoCredentialKeys(t, "k3s upgrade Plan", plan)
		})
	}
}

func TestRenderSeed_RefusesAPinOutOfShape(t *testing.T) {
	for _, tc := range []struct {
		name, field, value string
		mutate             func(*Versions, string)
	}{
		{"an empty kured chart version", "KuredChartVersion", "", func(v *Versions, s string) { v.KuredChartVersion = s }},
		{"a kured chart version carrying a second YAML line", "KuredChartVersion", "6.1.0\nconfiguration: {}", func(v *Versions, s string) { v.KuredChartVersion = s }},
		{"an empty system-upgrade-controller version", "SystemUpgradeControllerVersion", "", func(v *Versions, s string) { v.SystemUpgradeControllerVersion = s }},
		{"a system-upgrade-controller version carrying a second YAML line", "SystemUpgradeControllerVersion", "v0.20.2\nimages: []", func(v *Versions, s string) { v.SystemUpgradeControllerVersion = s }},
		{"a system-upgrade-controller version without the v prefix", "SystemUpgradeControllerVersion", "0.20.2", func(v *Versions, s string) { v.SystemUpgradeControllerVersion = s }},
		{"a k3s version without a patch and release suffix", "K3sVersion", "v1.36", func(v *Versions, s string) { v.K3sVersion = s }},
		{"a k3s version carrying a second YAML line", "K3sVersion", "v1.36.3+k3s1\nversion: v9.9.9", func(v *Versions, s string) { v.K3sVersion = s }},
		{"an empty traefik chart version", "TraefikChartVersion", "", func(v *Versions, s string) { v.TraefikChartVersion = s }},
		{"a traefik chart version carrying a second YAML line", "TraefikChartVersion", "41.6.1\nhostNetwork: false", func(v *Versions, s string) { v.TraefikChartVersion = s }},
		{"a traefik chart version with a v prefix", "TraefikChartVersion", "v41.6.1", func(v *Versions, s string) { v.TraefikChartVersion = s }},
		{"an empty cert-manager chart version", "CertManagerChartVersion", "", func(v *Versions, s string) { v.CertManagerChartVersion = s }},
		{"a cert-manager chart version without the v prefix", "CertManagerChartVersion", "1.21.2", func(v *Versions, s string) { v.CertManagerChartVersion = s }},
		{"a cert-manager chart version carrying a second YAML line", "CertManagerChartVersion", "v1.21.2\ncrds: {}", func(v *Versions, s string) { v.CertManagerChartVersion = s }},
		{"an empty kyverno chart version", "KyvernoChartVersion", "", func(v *Versions, s string) { setKyvernoVersion(v, s) }},
		{"a kyverno chart version with a v prefix", "KyvernoChartVersion", "v3.9.1", func(v *Versions, s string) { setKyvernoVersion(v, s) }},
		{"a kyverno chart version carrying a second YAML line", "KyvernoChartVersion", "3.9.1\nconfig: {}", func(v *Versions, s string) { setKyvernoVersion(v, s) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := PinnedVersions
			tc.mutate(&v, tc.value)

			_, err := RenderSeed(v, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)

			testutil.FatalIf(t, err == nil, "RenderSeed rendered with %s = %q, want a refusal", tc.field, tc.value)
			testutil.FailIf(t, !strings.Contains(err.Error(), tc.field), "RenderSeed refused %s = %q with %q, want the error to name %s", tc.field, tc.value, err, tc.field)
		})
	}
}

func assertChartApplication(t *testing.T, app map[string]any, name, repo, chart, version, namespace string) {
	t.Helper()
	what := name + " Application"
	testutil.AssertPaths(t, what, app, map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata.name": name, "metadata.namespace": "argocd",
		"spec.project": "default", "spec.source.repoURL": repo, "spec.source.chart": chart, "spec.source.targetRevision": version,
		"spec.source.helm.releaseName": name, "spec.destination": map[string]any{"server": inClusterAPI, "namespace": namespace},
	})
	automatedPruneSelfHeal(t, what, app)
	opts := stringsOf(t, what+" syncPolicy.syncOptions", testutil.Dig(app, "spec", "syncPolicy", "syncOptions"))
	if !slices.Contains(opts, "CreateNamespace=true") {
		t.Errorf("%s syncOptions = %q, want CreateNamespace=true among them, so the first sync creates the %s namespace", what, opts, namespace)
	}
	assertNoCredentialDeclared(t, what, app)
}

func TestRenderSeed_TraefikIsThePinnedChartAsAnApplicationThatPrunesAndSelfHeals(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := seedDoc(t, v, testutil.SeedTraefikPath)
		assertChartApplication(t, app, "traefik", "https://traefik.github.io/charts", "traefik", v.TraefikChartVersion, "traefik")
	})
}

func TestRenderSeed_TraefikRunsNonRootBehindTheLoadBalancersNodePortsAndTrustsOnlyItsAddress(t *testing.T) {
	app := seedDoc(t, PinnedVersions, testutil.SeedTraefikPath)
	values := testutil.ChartValues(t, "traefik Application", app)
	for _, v := range []struct {
		path []string
		want any
	}{
		{[]string{"hostNetwork"}, nil},
		{[]string{"service", "spec", "type"}, "NodePort"},
		{[]string{"service", "spec", "externalTrafficPolicy"}, "Local"},
		{[]string{"ports", "web", "nodePort"}, 30080},
		{[]string{"ports", "websecure", "nodePort"}, 30081},
		{[]string{"ports", "web", "proxyProtocol"}, map[string]any{"trustedIPs": []any{"10.255.0.254"}}},
		{[]string{"ports", "websecure", "proxyProtocol"}, map[string]any{"trustedIPs": []any{"10.255.0.254"}}},
		{[]string{"podSecurityContext", "runAsNonRoot"}, true},
		{[]string{"podSecurityContext", "runAsUser"}, 65532},
		{[]string{"securityContext", "capabilities"}, map[string]any{"drop": []any{"ALL"}}},
		{[]string{"providers", "kubernetesIngress", "publishedService", "enabled"}, false},
		{[]string{"updateStrategy", "rollingUpdate", "maxSurge"}, 0},
		{[]string{"updateStrategy", "rollingUpdate", "maxUnavailable"}, 1},
		{[]string{"ingressClass", "name"}, "traefik"},
	} {
		got := testutil.Dig(values, v.path...)
		testutil.FailIf(t, !reflect.DeepEqual(got, v.want), "traefik helm.values %s = %#v, want %#v", strings.Join(v.path, "."), got, v.want)
	}
	labels := testutil.Dig(app, "spec", "syncPolicy", "managedNamespaceMetadata", "labels")
	want := map[string]any{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}
	testutil.FailIf(t, !reflect.DeepEqual(labels, want), "traefik Application managedNamespaceMetadata.labels = %#v, want %#v", labels, want)
}

func TestRenderSeed_TraefikPublishesTheGivenPublicIPv4AsItsIngressAddress(t *testing.T) {
	renders := map[string]map[string]string{}
	for _, ip := range []string{"203.0.113.10", "198.51.100.77"} {
		files, err := RenderSeed(PinnedVersions, ip, testutil.FixtureRepoURL)
		testutil.FatalIf(t, err != nil, "RenderSeed with public IPv4 %s: %v", ip, err)
		renders[ip] = files
		values := testutil.ChartValues(t, "traefik Application", testutil.YamlMap(t, testutil.SeedTraefikPath, files[testutil.SeedTraefikPath]))
		got := testutil.Dig(values, "providers", "kubernetesIngress", "ingressEndpoint", "ip")
		testutil.FailIf(t, got != ip, "traefik helm.values providers.kubernetesIngress.ingressEndpoint.ip = %#v, want the given public IPv4 %q", got, ip)
	}
	for _, path := range testutil.WantSeedPaths {
		testutil.FailIf(t, path != testutil.SeedTraefikPath && renders["203.0.113.10"][path] != renders["198.51.100.77"][path], "%s differs between two public IPv4s, want only %s to carry the address", path, testutil.SeedTraefikPath)
	}
}

func TestRenderSeed_RefusesAPublicIPv4OutOfShape(t *testing.T) {
	for _, tc := range []struct{ name, ip string }{
		{"an empty address", ""},
		{"an address of three octets", "203.0.113"},
		{"an octet above 255", "203.0.113.256"},
		{"an IPv6 address", "2001:db8::10"},
		{"an IPv4-mapped IPv6 address", "::ffff:203.0.113.10"},
		{"an address with a leading space", " 203.0.113.10"},
		{"an address carrying a second YAML line", "203.0.113.10\nhostNetwork: false"},
		{"an address with a prefix length", "203.0.113.10/32"},
		{"a host name", "node.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, err := RenderSeed(PinnedVersions, tc.ip, testutil.FixtureRepoURL)

			testutil.FatalIf(t, err == nil, "RenderSeed rendered with public IPv4 %q, want a refusal; traefik.yaml is %q", tc.ip, files[testutil.SeedTraefikPath])
			testutil.FailIf(t, !strings.Contains(err.Error(), "PublicIPv4"), "RenderSeed refused public IPv4 %q with %q, want the error to name PublicIPv4", tc.ip, err)
		})
	}
}

func TestRenderSeed_CertManagerIsThePinnedChartWithItsCRDsAsAnApplicationThatPrunesAndSelfHeals(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := seedDoc(t, v, seedCertManagerPath)
		assertChartApplication(t, app, "cert-manager", "https://charts.jetstack.io", "cert-manager", v.CertManagerChartVersion, "cert-manager")
		got := testutil.Dig(testutil.ChartValues(t, "cert-manager Application", app), "crds", "enabled")
		testutil.FailIf(t, got != true, "cert-manager helm.values crds.enabled = %#v, want true, so the chart installs the ClusterIssuer and Certificate CRDs", got)
		digest := testutil.Dig(testutil.ChartValues(t, "cert-manager Application", app), "acmesolver", "image", "digest")
		testutil.FailIf(t, digest != acmesolverDigests[v.CertManagerChartVersion], "cert-manager helm.values acmesolver.image.digest = %#v for chart %s, want %q, the digest recorded for that version", digest, v.CertManagerChartVersion, acmesolverDigests[v.CertManagerChartVersion])
	})
}

const (
	acmesolverUpstreamRepository = "quay.io/jetstack/cert-manager-acmesolver"
	acmesolverPinnedDigest       = "sha256:699b40d622211ab7accad8a21b04c5fbaa1841ef7a12621e8de492dbe27b2503"
	acmeSolverLabel              = "mitstack.dev/app"
	acmeSolverLabelValue         = "acme-http01-solver"
)

func TestRenderSeed_CertManagerPinsTheACMESolverImageByDigestAndKeepsItsUpstreamRepository(t *testing.T) {
	app := seedDoc(t, PinnedVersions, seedCertManagerPath)

	values := testutil.ChartValues(t, "cert-manager Application", app)

	testutil.AssertValues(t, "cert-manager helm.values", map[string]any{
		"acmesolver":   values["acmesolver"],
		"crds.enabled": testutil.Dig(values, "crds", "enabled"),
	}, map[string]any{
		"acmesolver":   map[string]any{"image": map[string]any{"digest": acmesolverPinnedDigest}},
		"crds.enabled": true,
	})
}

func TestAdmission_RegistryPolicyPinsExactlyTheACMESolverImageTheChartRunsAndTheCloudNativePGImages(t *testing.T) {
	got := pinnedImages(t)

	want := []string{acmesolverUpstreamRepository + "@" + acmesolverDigests[PinnedVersions.CertManagerChartVersion], wantOperatorImage, wantPostgres16Image}

	testutil.FailIf(t, !slices.Equal(got, want), "mitstack-restrict-image-registries pinnedImages = %q; want exactly %q: the image chart %s runs, the CloudNativePG operator and its Postgres 16 image", got, want, PinnedVersions.CertManagerChartVersion)
}

func TestRenderSeed_ACMESolverDigestIsRecordedForThePinnedChartVersion(t *testing.T) {
	got := acmesolverDigests[PinnedVersions.CertManagerChartVersion]

	testutil.FailIf(t, got != acmesolverPinnedDigest, "acmesolverDigests[%q] = %q; want %q", PinnedVersions.CertManagerChartVersion, got, acmesolverPinnedDigest)
}

func TestRenderSeed_RefusesACertManagerChartVersionWithNoRecordedACMESolverDigest(t *testing.T) {
	v := PinnedVersions
	v.CertManagerChartVersion = "v1.21.3"

	files, err := RenderSeed(v, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)

	testutil.FatalIf(t, err == nil, "RenderSeed with CertManagerChartVersion %q rendered %d files; want an error naming the missing acmesolver digest", v.CertManagerChartVersion, len(files))
	testutil.FailIf(t, !strings.Contains(err.Error(), "acmesolver digest") || !strings.Contains(err.Error(), "v1.21.3"), "RenderSeed with CertManagerChartVersion %q = %q; want an error naming the acmesolver digest and the version", v.CertManagerChartVersion, err)
}

func acmeSolverFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("admission/tests/acme-http01-solver/" + name)
	testutil.FatalIf(t, err != nil, "reading the %s solver pod fixture: %v", name, err)
	return testutil.YamlMap(t, name, string(raw))
}

func solverImage(t *testing.T, pod map[string]any) string {
	t.Helper()
	containers, ok := testutil.Dig(pod, "spec", "containers").([]any)
	testutil.FatalIf(t, !ok || len(containers) != 1, "solver pod spec.containers = %#v; want exactly one container", testutil.Dig(pod, "spec", "containers"))
	image, _ := containers[0].(map[string]any)["image"].(string)
	return image
}

func TestRenderSeed_ACMESolverPodFixturesMatchWhatTheBlockShips(t *testing.T) {
	values := testutil.ChartValues(t, "cert-manager Application", seedDoc(t, PinnedVersions, seedCertManagerPath))
	issuer := seedDoc(t, PinnedVersions, seedClusterIssuerPath)
	solvers, _ := testutil.Dig(issuer, "spec", "acme", "solvers").([]any)
	testutil.FatalIf(t, len(solvers) != 1, "ClusterIssuer spec.acme.solvers = %#v; want exactly one solver", solvers)
	podLabels, _ := testutil.Dig(solvers[0], "http01", "ingress", "podTemplate", "metadata", "labels").(map[string]any)

	admitted, today := acmeSolverFixture(t, "admitted.yaml"), acmeSolverFixture(t, "today.yaml")

	wantAdmitted := fmt.Sprintf("%s@%v", acmesolverUpstreamRepository, testutil.Dig(values, "acmesolver", "image", "digest"))
	testutil.FailIf(t, solverImage(t, admitted) != wantAdmitted, "admitted.yaml image = %q; want %q, the upstream repository and the digest the cert-manager values name", solverImage(t, admitted), wantAdmitted)
	testutil.FatalIf(t, len(podLabels) == 0, "ClusterIssuer podTemplate labels = %#v; want the labels the solver pod carries", podLabels)
	fixtureLabels, _ := testutil.Dig(admitted, "metadata", "labels").(map[string]any)
	for k, v := range podLabels {
		testutil.FailIf(t, fixtureLabels[k] != v, "admitted.yaml label %s = %#v; want %#v, as the ClusterIssuer podTemplate sets", k, fixtureLabels[k], v)
	}
	wantToday := "quay.io/jetstack/cert-manager-acmesolver:" + PinnedVersions.CertManagerChartVersion
	testutil.FailIf(t, solverImage(t, today) != wantToday, "today.yaml image = %q; want %q, the upstream image of the pinned chart", solverImage(t, today), wantToday)
}

func TestRenderSeed_ClusterIssuerSolvesHTTP01ThroughTraefikAgainstLetsEncryptProduction(t *testing.T) {
	issuer := seedDoc(t, PinnedVersions, seedClusterIssuerPath)
	testutil.AssertValues(t, "ClusterIssuer", map[string]any{
		"apiVersion": issuer["apiVersion"], "kind": issuer["kind"],
		"name":        testutil.Dig(issuer, "metadata", "name"),
		"syncOptions": testutil.Dig(issuer, "metadata", "annotations", "argocd.argoproj.io/sync-options"),
	}, map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer",
		"name":        "letsencrypt-production",
		"syncOptions": "SkipDryRunOnMissingResource=true",
	})
	ns := testutil.Dig(issuer, "metadata", "namespace")
	testutil.FailIf(t, ns != nil, "ClusterIssuer metadata.namespace = %#v, want none: a ClusterIssuer is cluster-scoped", ns)
	server := testutil.Dig(issuer, "spec", "acme", "server")
	testutil.FailIf(t, server != "https://acme-v02.api.letsencrypt.org/directory", "ClusterIssuer spec.acme.server = %#v, want Let's Encrypt's production directory", server)
	name, _ := testutil.Dig(issuer, "spec", "acme", "privateKeySecretRef", "name").(string)
	testutil.FailIf(t, strings.TrimSpace(name) == "", "ClusterIssuer spec.acme.privateKeySecretRef.name = %#v, want the Secret that holds the ACME account key", testutil.Dig(issuer, "spec", "acme", "privateKeySecretRef", "name"))
	solvers, ok := testutil.Dig(issuer, "spec", "acme", "solvers").([]any)
	testutil.FatalIf(t, !ok || len(solvers) != 1, "ClusterIssuer spec.acme.solvers = %#v, want exactly one solver", testutil.Dig(issuer, "spec", "acme", "solvers"))
	want := map[string]any{"http01": map[string]any{"ingress": map[string]any{
		"ingressClassName": "traefik",
		"serviceType":      "ClusterIP",
		"podTemplate":      map[string]any{"metadata": map[string]any{"labels": map[string]any{acmeSolverLabel: acmeSolverLabelValue}}},
	}}}
	testutil.FailIf(t, !reflect.DeepEqual(solvers[0], want), "ClusterIssuer solver = %#v, want exactly %#v, with a ClusterIP solver Service, since an app slice's quota allows no NodePort Service", solvers[0], want)
}

func TestRenderSeed_IngressAndCertManagerComeFromTheSeedNeverFromK3sManifests(t *testing.T) {
	files := seedFiles(t, PinnedVersions)
	for path, name := range map[string]string{testutil.SeedTraefikPath: "traefik", seedCertManagerPath: "cert-manager"} {
		app := testutil.YamlMap(t, path, files[path])
		testutil.FailIf(t, app["kind"] != "Application" || testutil.Dig(app, "metadata", "name") != name, "%s holds a %v named %v, want the %s Application", path, app["kind"], testutil.Dig(app, "metadata", "name"), name)
	}

	_, cc := renderCC(t, fixtureRenderInputs())
	for _, f := range cc.WriteFiles {
		if !strings.HasPrefix(f.Path, manifestsDir+"/") {
			continue
		}
		for _, doc := range testutil.YamlDocs(t, f.Path, f.Content) {
			if doc["kind"] != "HelmChart" {
				continue
			}
			for _, chart := range []string{"traefik", "cert-manager"} {
				testutil.FailIf(t, testutil.Dig(doc, "metadata", "name") == chart || testutil.Dig(doc, "spec", "chart") == chart, "%s carries a HelmChart for %s, which k3s reinstalls on every restart; it belongs to Argo CD in the seed", f.Path, chart)
			}
		}
	}
	config := testutil.YamlMap(t, "k3s config.yaml", cc.File(t, "/etc/rancher/k3s/config.yaml").Content)
	disabled := stringsOf(t, "k3s config.yaml disable", config["disable"])
	testutil.FailIf(t, !slices.Contains(disabled, "traefik"), "k3s config.yaml disable = %q, want traefik among them, so k3s runs no Traefik of its own beside the seeded one", disabled)
}

func TestRenderSeed_ArgoCDCreatesNeitherTheNotificationsConfigMapNorItsSecret(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		chart := bootstrapHelmCharts(t, v)["argocd"]
		bootValues, ok := testutil.Dig(chart, "spec", "valuesContent").(string)
		testutil.FatalIf(t, !ok, "the argocd HelmChart spec.valuesContent is %T, want the values text", testutil.Dig(chart, "spec", "valuesContent"))
		for what, values := range map[string]map[string]any{
			"the argocd HelmChart's valuesContent":        testutil.YamlMap(t, "argocd valuesContent", bootValues),
			"the seeded argocd Application's helm.values": testutil.ChartValues(t, "argocd Application", seedDoc(t, v, testutil.SeedArgoCDPath)),
		} {
			for _, path := range [][]string{{"notifications", "cm", "create"}, {"notifications", "secret", "create"}, {"dex", "enabled"}} {
				got := testutil.Dig(values, path...)
				testutil.FailIf(t, got != false, "%s %s = %#v, want false", what, strings.Join(path, "."), got)
			}
		}
	})
}

var notificationTriggers = map[string]map[string]any{
	"on-deployed": {
		"when":    "app.status.operationState != nil and app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'",
		"oncePer": "app.status.operationState?.syncResult?.revision",
		"send":    []any{"mitstack"},
	},
	"on-sync-failed": {
		"when": "app.status.operationState != nil and app.status.operationState.phase in ['Error', 'Failed']",
		"send": []any{"mitstack"},
	},
	"on-health-degraded": {
		"when": "app.status.health.status == 'Degraded'",
		"send": []any{"mitstack"},
	},
}

func notificationsConfigMap(t *testing.T, v Versions) map[string]any {
	t.Helper()
	return seedDoc(t, v, testutil.SeedNotificationsPath)
}

func notificationsEntry(t *testing.T, cm map[string]any, key string) any {
	t.Helper()
	raw, ok := testutil.Dig(cm, "data", key).(string)
	testutil.FatalIf(t, !ok, "argocd-notifications-cm data[%q] is %T, want a string of YAML", key, testutil.Dig(cm, "data", key))
	var v any
	err := yaml.Unmarshal([]byte(raw), &v)
	testutil.FatalIf(t, err != nil, "argocd-notifications-cm data[%q] is not YAML: %v\n%s", key, err, raw)
	return v
}

func TestCarriesTokenShape_SkipsAnImageDigestAndAHelmChecksumAndStillFlagsABareValue(t *testing.T) {
	digest := strings.Repeat("a1", 32)

	testutil.FailIf(t, testutil.CarriesTokenShape("image: ghcr.io/mitstack-eu/probe@sha256:"+digest+"\n"), "a sha256 image digest read as a token")
	testutil.FailIf(t, !testutil.CarriesTokenShape("image: ghcr.io/mitstack-eu/probe@sha256:"+digest+"\ntoken: "+digest+"\n"), "a bare 64-hex value beside a digest passed the guard")
	testutil.FailIf(t, !testutil.CarriesTokenShape("token: "+digest), "a bare 64-hex value passed the guard")
	testutil.FailIf(t, testutil.CarriesTokenShape("      annotations:\n        checksum/rbac: "+digest+"\n"), "a Helm checksum annotation read as a token")
	testutil.FailIf(t, !testutil.CarriesTokenShape("        checksum/rbac: "+digest+"\n        token: "+digest+"\n"), "a bare 64-hex value beside a Helm checksum passed the guard")
}

func TestRenderSeed_NotificationsConfigMapPostsEverySyncOutcomeToThePlatform(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		cm := notificationsConfigMap(t, v)
		testutil.AssertPaths(t, "argocd-notifications-cm", cm, map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap", "metadata.name": "argocd-notifications-cm", "metadata.namespace": "argocd",
		})
		data, ok := cm["data"].(map[string]any)
		testutil.FatalIf(t, !ok, "argocd-notifications-cm data is %T, want a mapping", cm["data"])
		wantKeys := []string{"service.webhook.mitstack", "subscriptions", "template.mitstack",
			"trigger.on-deployed", "trigger.on-health-degraded", "trigger.on-sync-failed"}
		keys := slices.Sorted(maps.Keys(data))
		testutil.FailIf(t, !slices.Equal(keys, wantKeys), "argocd-notifications-cm data has keys %v, want exactly %v", keys, wantKeys)

		service, ok := notificationsEntry(t, cm, "service.webhook.mitstack").(map[string]any)
		testutil.FatalIf(t, !ok, "service.webhook.mitstack is not a mapping")
		headers, ok := service["headers"].([]any)
		testutil.FatalIf(t, !ok, "service.webhook.mitstack headers is %T, want a list", service["headers"])
		gotHeaders := map[string]any{}
		for i, h := range headers {
			hm, ok := h.(map[string]any)
			testutil.FatalIf(t, !ok, "service.webhook.mitstack headers[%d] is %T, want a mapping", i, h)
			keys := slices.Sorted(maps.Keys(hm))
			testutil.FailIf(t, !slices.Equal(keys, []string{"name", "value"}), "service.webhook.mitstack headers[%d] has keys %v, want exactly [name value]", i, keys)
			name, _ := hm["name"].(string)
			_, dup := gotHeaders[name]
			testutil.FailIf(t, dup, "service.webhook.mitstack sets the header %s twice", name)
			gotHeaders[name] = hm["value"]
		}
		testutil.AssertValues(t, "service.webhook.mitstack headers", gotHeaders, map[string]any{
			"Authorization": "Bearer $platform-token",
			"Content-Type":  "application/json",
		})
		delete(service, "headers")
		testutil.AssertValues(t, "service.webhook.mitstack", service, map[string]any{"url": gitOpsNotificationsURL})

		tmpl, ok := notificationsEntry(t, cm, "template.mitstack").(map[string]any)
		testutil.FatalIf(t, !ok, "template.mitstack is not a mapping")
		keys2 := slices.Sorted(maps.Keys(tmpl))
		testutil.FailIf(t, !slices.Equal(keys2, []string{"webhook"}), "template.mitstack has keys2 %v, want exactly [webhook]", keys2)
		webhooks, ok := tmpl["webhook"].(map[string]any)
		testutil.FatalIf(t, !ok, "template.mitstack webhook is %T, want a mapping", tmpl["webhook"])
		keys3 := slices.Sorted(maps.Keys(webhooks))
		testutil.FailIf(t, !slices.Equal(keys3, []string{"mitstack"}), "template.mitstack webhook has keys3 %v, want exactly [mitstack], the one service", keys3)
		hook, ok := webhooks["mitstack"].(map[string]any)
		testutil.FatalIf(t, !ok, "template.mitstack webhook.mitstack is %T, want a mapping", webhooks["mitstack"])
		body, _ := hook["body"].(string)
		testutil.FailIf(t, strings.TrimSpace(body) == "", "template.mitstack webhook.mitstack.body is %#v, want the JSON body template", hook["body"])
		testutil.AssertValues(t, "template.mitstack webhook.mitstack", hook, map[string]any{"method": "POST", "body": hook["body"]})

		for name, want := range notificationTriggers {
			entry := notificationsEntry(t, cm, "trigger."+name)
			conditions, ok := entry.([]any)
			if !ok || len(conditions) != 1 {
				t.Errorf("trigger.%s = %#v, want a list of exactly one condition", name, entry)
				continue
			}
			condition, ok := conditions[0].(map[string]any)
			if !ok {
				t.Errorf("trigger.%s[0] is %T, want a mapping", name, conditions[0])
				continue
			}
			got := maps.Clone(condition)
			if when, ok := got["when"].(string); ok {
				got["when"] = strings.Join(strings.Fields(when), " ")
			}
			testutil.AssertValues(t, "trigger."+name, got, want)
		}

		entry := notificationsEntry(t, cm, "subscriptions")
		subs, ok := entry.([]any)
		testutil.FatalIf(t, !ok || len(subs) != 1, "subscriptions = %#v, want exactly one default subscription", entry)
		sub, ok := subs[0].(map[string]any)
		testutil.FatalIf(t, !ok, "subscriptions[0] is %T, want a mapping", subs[0])
		keys4 := slices.Sorted(maps.Keys(sub))
		testutil.FailIf(t, !slices.Equal(keys4, []string{"recipients", "triggers"}), "subscriptions[0] has keys4 %v, want exactly [recipients triggers], so it selects every Application", keys4)
		got := stringsOf(t, "subscriptions[0].recipients", sub["recipients"])
		testutil.FailIf(t, !slices.Equal(got, []string{"mitstack"}), "subscriptions[0].recipients = %q, want exactly [mitstack]", got)
		triggers := stringsOf(t, "subscriptions[0].triggers", sub["triggers"])
		slices.Sort(triggers)
		want := slices.Sorted(maps.Keys(notificationTriggers))
		testutil.FailIf(t, !slices.Equal(triggers, want), "subscriptions[0].triggers = %q, want exactly %q", triggers, want)

		raw := seedFiles(t, v)[testutil.SeedNotificationsPath]
		testutil.FailIf(t, testutil.CarriesTokenShape(raw), "%s carries a value in the notification token's shape; it must name the Secret key $platform-token only", testutil.SeedNotificationsPath)
	})
}

const spikeRevision = "9ee9b7e28c000b16a89b7b717e5f3b9fa6fcf611"

func spikeApplication() map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": "app-alpha", "namespace": "argocd"},
		"spec":     map[string]any{"project": "app-alpha"},
		"status": map[string]any{
			"sync":         map[string]any{"status": "Synced", "revision": spikeRevision},
			"health":       map[string]any{"status": "Healthy"},
			"reconciledAt": "2026-09-28T10:47:23Z",
			"operationState": map[string]any{
				"phase":      "Succeeded",
				"message":    "successfully synced (all tasks run)",
				"syncResult": map[string]any{"revision": spikeRevision},
			},
		},
	}
}

func sprigToJSON(v any) string {
	out, _ := json.Marshal(v)
	return string(out)
}

func sprigDig(ps ...any) (any, error) {
	if len(ps) < 3 {
		return nil, fmt.Errorf("dig takes keys, a default and a map, got %d arguments", len(ps))
	}
	dict, ok := ps[len(ps)-1].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dig's last argument is %T, want map[string]interface {}", ps[len(ps)-1])
	}
	def := ps[len(ps)-2]
	keys := ps[:len(ps)-2]
	for i, k := range keys {
		key, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("dig key %d is %T, want a string", i, k)
		}
		step, has := dict[key]
		if !has {
			return def, nil
		}
		if i == len(keys)-1 {
			return step, nil
		}
		if dict, ok = step.(map[string]any); !ok {
			return nil, fmt.Errorf("dig: %s is %T, not a map", key, step)
		}
	}
	return def, nil
}

func notificationBody(t *testing.T) *template.Template {
	t.Helper()
	tmpl := notificationsEntry(t, notificationsConfigMap(t, PinnedVersions), "template.mitstack")
	body, ok := testutil.Dig(tmpl, "webhook", "mitstack", "body").(string)
	testutil.FatalIf(t, !ok, "template.mitstack webhook.mitstack.body is %T, want the body template", testutil.Dig(tmpl, "webhook", "mitstack", "body"))
	parsed, err := template.New("template.mitstack").
		Funcs(template.FuncMap{"toJson": sprigToJSON, "dig": sprigDig}).
		Parse(body)
	testutil.FatalIf(t, err != nil, "the webhook body does not parse as a Go template calling only toJson and dig: %v\n%s", err, body)
	return parsed
}

func TestRenderSeed_NotificationBodyIsTheEightFieldsThePlatformStoresAsJSONStrings(t *testing.T) {
	spike := map[string]any{
		"app": "app-alpha", "project": "app-alpha", "sync": "Synced", "revision": spikeRevision,
		"health": "Healthy", "phase": "Succeeded", "message": "successfully synced (all tasks run)",
		"reconciledAt": "2026-09-28T10:47:23Z",
	}
	with := func(fields map[string]any) map[string]any {
		w := maps.Clone(spike)
		maps.Copy(w, fields)
		return w
	}
	const awkward = "one or more objects failed to apply, reason: Deployment \"web\" is invalid\nspec.replicas: must be non-negative"
	const newerRevision = "1f3c0de5a9b8e7d6c5b4a3928170f6e5d4c3b2a1"
	for _, tc := range []struct {
		name   string
		mutate func(app map[string]any)
		want   map[string]any
	}{
		{"the spike's app-alpha", func(map[string]any) {}, spike},
		{"an Application with no operationState", func(app map[string]any) {
			delete(testutil.Dig(app, "status").(map[string]any), "operationState")
		}, with(map[string]any{"phase": "", "message": "", "revision": spikeRevision})},
		{"a message carrying a double quote and a newline", func(app map[string]any) {
			op := testutil.Dig(app, "status", "operationState").(map[string]any)
			op["phase"], op["message"] = "Failed", awkward
		}, with(map[string]any{"phase": "Failed", "message": awkward})},
		{"a sync revision newer than the operation synced", func(app map[string]any) {
			testutil.Dig(app, "status", "sync").(map[string]any)["revision"] = newerRevision
		}, spike},
		{"an operation with no syncResult", func(app map[string]any) {
			delete(testutil.Dig(app, "status", "operationState").(map[string]any), "syncResult")
			testutil.Dig(app, "status", "sync").(map[string]any)["revision"] = newerRevision
		}, with(map[string]any{"revision": newerRevision})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := spikeApplication()
			tc.mutate(app)
			var out strings.Builder
			err := notificationBody(t).Execute(&out, map[string]any{"app": app})
			testutil.FatalIf(t, err != nil, "executing the webhook body: %v", err)
			var got map[string]any
			err2 := json.Unmarshal([]byte(out.String()), &got)
			testutil.FatalIf(t, err2 != nil, "the webhook body renders as %q, which is not one JSON object: %v", out.String(), err2)
			for k, v := range got {
				_, ok := v.(string)
				testutil.FailIf(t, !ok, "the rendered body's %s is %#v, want a JSON string, or the platform answers 400", k, v)
			}
			testutil.AssertValues(t, "the rendered webhook body", got, tc.want)
		})
	}
}

const (
	seedKyvernoPath         = "cluster/kyverno.yaml"
	seedProbeNamespacePath  = "cluster/admission-probe-namespace.yaml"
	seedProbeFixturesPath   = "cluster/admission-probe-fixtures.yaml"
	podSecurityRuleName     = "pod-security-restricted"
	admissionFixturesConfig = "admission-fixtures"
)

func kyvernoVersion(v Versions) string { return v.KyvernoChartVersion }

func setKyvernoVersion(v *Versions, s string) { v.KyvernoChartVersion = s }

func TestRenderVersions_PinKyvernoChartAt391(t *testing.T) {
	got := kyvernoVersion(PinnedVersions)

	testutil.FailIf(t, got != "3.9.1", "PinnedVersions.KyvernoChartVersion = %q, want 3.9.1, the chart that runs Kyverno v1.19.1", got)
}

func seedPolicyPath(policy string) string { return "cluster/admission-policy-" + policy + ".yaml" }

func TestRenderSeed_KyvernoIsThePinnedChartAsAnApplicationSyncedServerSide(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := seedDoc(t, v, seedKyvernoPath)

		assertChartApplication(t, app, "kyverno", "https://kyverno.github.io/kyverno/", "kyverno", kyvernoVersion(v), "kyverno")

		opts := stringsOf(t, "kyverno syncPolicy.syncOptions", testutil.Dig(app, "spec", "syncPolicy", "syncOptions"))
		testutil.FailIf(t, !slices.Contains(opts, "ServerSideApply=true"), "kyverno Application syncOptions = %q, want ServerSideApply=true among them, since Kyverno's CRDs exceed the client-side apply annotation", opts)
	})
}

func TestRenderSeed_KyvernoWebhooksLeaveTheSystemNamespacesAlone(t *testing.T) {
	app := seedDoc(t, PinnedVersions, seedKyvernoPath)

	got := testutil.Dig(testutil.ChartValues(t, "kyverno Application", app), "config", "webhooks")

	want := map[string]any{"namespaceSelector": map[string]any{"matchExpressions": []any{
		map[string]any{"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": stringList(admissionSystemNamespaces)},
	}}}
	testutil.FailIf(t, !reflect.DeepEqual(got, want), "kyverno helm.values config.webhooks = %#v, want %#v, so a Kyverno outage cannot block a system pod", got, want)
}

func TestRenderSeed_CarriesEachAdmissionPolicyByteForByte(t *testing.T) {
	files := seedFiles(t, PinnedVersions)
	for _, policy := range admissionPolicyNames {
		t.Run(policy, func(t *testing.T) {
			want := admissionFile(t, admissionPoliciesDir, policy+".yaml")

			got := files[seedPolicyPath(policy)]

			testutil.FailIf(t, got != want, "%s is %d bytes, want the %d bytes of %s/%s.yaml", seedPolicyPath(policy), len(got), len(want), admissionPoliciesDir, policy)
		})
	}
}

func TestRenderSeed_ProbeNamespaceEnforcesPodSecurityRestricted(t *testing.T) {
	ns := seedDoc(t, PinnedVersions, seedProbeNamespacePath)

	labels, _ := testutil.Dig(ns, "metadata", "labels").(map[string]any)
	testutil.AssertPaths(t, "the probe namespace", ns, map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata.name": admissionProbeNamespace,
	})
	testutil.FailIf(t, labels["pod-security.kubernetes.io/enforce"] != "restricted" || labels["pod-security.kubernetes.io/enforce-version"] != "latest",
		"the probe namespace labels = %v, want pod-security.kubernetes.io/enforce restricted and enforce-version latest", labels)
}

func TestRenderSeed_FixturesConfigMapHoldsEachRulesRefusedManifestUnderTheRuleName(t *testing.T) {
	cm := seedDoc(t, PinnedVersions, seedProbeFixturesPath)

	testutil.AssertPaths(t, "the fixtures ConfigMap", cm, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata.name": admissionFixturesConfig, "metadata.namespace": admissionProbeNamespace,
	})
	want := map[string]any{podSecurityRuleName: admissionFile(t, admissionProbeFile)}
	for _, policy := range admissionValidatingPolicies {
		want[policy] = admissionFile(t, admissionTestsDir, policy, "refused.yaml")
	}
	data, _ := cm["data"].(map[string]any)
	testutil.AssertValues(t, "the fixtures ConfigMap data", data, want)
}

const syncWaveAnnotation = "argocd.argoproj.io/sync-wave"

// crdProviders names, for each API group the seed holds a custom resource of, the seeded Application that installs the group's CRDs.
var crdProviders = map[string]string{
	"upgrade.cattle.io":   "system-upgrade-controller",
	"cert-manager.io":     "cert-manager",
	"policies.kyverno.io": "kyverno",
	"kyverno.io":          "kyverno",
}

// syncWave reads a document's wave as Argo CD does, 0 when the annotation is absent.
func syncWave(t *testing.T, what string, doc map[string]any) int {
	t.Helper()
	raw := testutil.Dig(doc, "metadata", "annotations", syncWaveAnnotation)
	if raw == nil {
		return 0
	}
	text, ok := raw.(string)
	testutil.FatalIf(t, !ok, "%s %s is %#v, want a quoted integer", what, syncWaveAnnotation, raw)
	wave, err := strconv.Atoi(text)
	testutil.FatalIf(t, err != nil, "%s %s = %q, want an integer: %v", what, syncWaveAnnotation, text, err)
	return wave
}

type seedResource struct {
	path, kind, name, provider string
	doc                        map[string]any
}

func seedCustomResources(t *testing.T, files map[string]string) (map[string]map[string]any, []seedResource) {
	t.Helper()
	apps := map[string]map[string]any{}
	var resources []seedResource
	for _, path := range slices.Sorted(maps.Keys(files)) {
		if !strings.HasSuffix(path, ".yaml") {
			continue
		}
		for _, doc := range testutil.YamlDocs(t, path, files[path]) {
			kind, _ := doc["kind"].(string)
			name, _ := testutil.Dig(doc, "metadata", "name").(string)
			if kind == "Application" {
				apps[name] = doc
				continue
			}
			apiVersion, _ := doc["apiVersion"].(string)
			group, _, _ := strings.Cut(apiVersion, "/")
			if provider, ok := crdProviders[group]; ok {
				resources = append(resources, seedResource{path: path, kind: kind, name: name, provider: provider, doc: doc})
			}
		}
	}
	return apps, resources
}

func TestRenderSeed_EachCRDInstallingApplicationSyncsInAnEarlierWaveThanEveryResourceOfItsKinds(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		apps, resources := seedCustomResources(t, seedFiles(t, v))

		found := map[string]bool{}
		for _, r := range resources {
			found[r.kind+"/"+r.name] = true
		}
		want := []string{"Plan/k3s-server", "ClusterIssuer/letsencrypt-production"}
		for _, policy := range admissionPolicyNames {
			kind := map[string]string{admissionGeneratorName: "GeneratingPolicy", signaturePolicy: "ImageValidatingPolicy"}[policy]
			if kind == "" {
				kind = "ValidatingPolicy"
			}
			want = append(want, kind+"/"+policy)
		}
		for _, w := range want {
			testutil.FatalIf(t, !found[w], "the seed holds no %s among its custom resources %v, so the wave check below would pin nothing for it", w, slices.Sorted(maps.Keys(found)))
		}

		for _, r := range resources {
			app, ok := apps[r.provider]
			if !ok {
				t.Errorf("%s holds a %s, and the seed has no %s Application to install its CRD", r.path, r.kind, r.provider)
				continue
			}
			appWave := syncWave(t, r.provider+" Application", app)
			resourceWave := syncWave(t, r.path, r.doc)
			testutil.FailIf(t, appWave >= resourceWave, "the %s Application syncs in wave %d and the %s %s in %s in wave %d, want the Application in an earlier wave, so Argo CD applies the %s once its CRD exists", r.provider, appWave, r.kind, r.name, r.path, resourceWave, r.kind)
		}
	})
}
