package cluster

// bootcomponents_test.go pins how mitstack's own cluster, whose subscription sets hostsPlatform, boots with no platform running.

import (
	"fmt"
	"maps"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	credentialFile     = testutil.BootDir + "/03-cluster-repository.yaml"
	enrolTimerPath     = systemdDir + "/mitstack-enrol.timer"
	wantOpenBaoDataDir = "/var/lib/openbao"

	// wantOpenBaoCADir is where each pod that calls OpenBao mounts the ConfigMap openbao-ca, and mitstack-openbao reads ca.crt.
	wantOpenBaoCADir = "/etc/mitstack/openbao-ca"
)

// wantBootTrees is what `git rev-parse v0.5.0:<dir>` answers in mitstack-eu/cluster-bases for each boot component.
var wantBootTrees = map[string]string{
	"openbao":          "77f51483e46bf7c807e55e077715fa85eeea68d3",
	"cert-manager":     "e4f72d0f4d17a47fc61aa2dcc0cdd696abbbf826",
	"trust-manager":    "4ecf1aaf5bf9d2055d16f18a0c4bb1f675e3135d",
	"external-secrets": "e92ccf702e373c89cbba5470da9e01b7c0a8500d",
	"traefik":          "e80568c1ae9f33d598c1dbf55ae48c1234360351",
	"sealed-secrets":   "559ed2bdbfe2497fe523cc0d69ecab6e3cdd93a7",
}

var listenerBlockRe = regexp.MustCompile(`(?s)listener "tcp" \{(.*?)\}`)

// bootFixture reads a test-only key or file from testdata/boot, which the boot proof also runs with.
func bootFixture(name string) string {
	raw, err := os.ReadFile("testdata/boot/" + name)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func hostsPlatformRenderInputs() UserDataInputs {
	in := fixtureRenderInputs()
	app, err := ReadSealedAppKey(bootFixture("github-app-key.sealed.yaml"))
	if err != nil {
		panic(err)
	}
	in.HostsPlatform = &HostsPlatformInputs{SealKey: testutil.FixtureSealKey, AppID: testutil.FixtureGitHubAppID, InstallationID: testutil.FixtureInstallationID, PublicIPv4: testutil.FixtureIngressIPv4,
		Recipient: bootFixture("owner.asc"), SealedSecrets: SealedSecretsInputs{KeyPEM: bootFixture("sealed-secrets.key"), CertPEM: bootFixture("sealed-secrets.crt"), SealedAppKey: app}}
	return in
}

// imageTags lists every tag a chart's values set, at any depth.
func imageTags(v any) []string {
	var tags []string
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if s, ok := child.(string); ok && k == "tag" {
				tags = append(tags, s)
			}
			tags = append(tags, imageTags(child)...)
		}
	case []any:
		for _, child := range x {
			tags = append(tags, imageTags(child)...)
		}
	}
	return tags
}

func chartValuesOf(t *testing.T, what string, chart map[string]any) map[string]any {
	t.Helper()
	text, ok := testutil.Dig(chart, "spec", "valuesContent").(string)
	testutil.FatalIf(t, !ok, "%s carries no valuesContent", what)
	return testutil.YamlMap(t, what+" values", text)
}

func TestClusterBases_TheBlockCarriesEachBootComponentAsTheReleaseHoldsIt(t *testing.T) {
	for component, want := range wantBootTrees {
		t.Run(component, func(t *testing.T) {
			entries, err := os.ReadDir("clusterbases/" + component)
			testutil.FatalIf(t, err != nil, "reading clusterbases/%s: %v", component, err)
			files := map[string]string{}
			for _, e := range entries {
				files[e.Name()] = testutil.TestRepoFile(t, "clusterbases/"+component+"/"+e.Name())
			}

			got := gitTreeID(files)

			testutil.FailIf(t, got != want, "clusterbases/%s is git tree %s holding %v, want %s, its tree at cluster-bases %s", component, got, slices.Sorted(maps.Keys(files)), want, wantClusterBasesTag)
		})
	}
}

func TestRenderUserData_HostsPlatformStartsK3sWithoutWaitingForEnrolment(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())

	got := strings.Split(runcmdChain(t, cc), " && ")

	want := []string{sshMask, "systemctl daemon-reload", metadataGuardStart, "install -d -m 0700 " + wantOpenBaoDataDir, cc.NodeScript(t).Path,
		autoUpgradeEnable, aptDailyRefreshNow, cc.Installer(t).Path, "systemctl enable --now k3s", "systemctl enable --now mitstack-enrol.timer"}
	testutil.FailIf(t, !slices.Equal(got, want), "runcmd = %q\nwant %q", got, want)
	for _, f := range cc.WriteFiles {
		testutil.FailIf(t, f.Path == k3sEnrolDropIn, "the user data writes %s, so k3s would wait for enrolment", k3sEnrolDropIn)
	}
	testutil.FailIf(t, cc.EnrolScript(t).Path != enrolScriptPath, "the enrol script is at %s, want %s", cc.EnrolScript(t).Path, enrolScriptPath)
	for _, r := range []unitRow{
		{name: "the enrol unit still runs the enrol script", path: enrolUnitPath, one: map[string]string{"Service.ExecStart": enrolScriptPath}},
		{name: "a timer retries enrolment until the platform answers", path: enrolTimerPath, perms: "0644", timerOf: enrolUnitName,
			listed: []string{"Install.WantedBy=timers.target"}, one: map[string]string{"Timer.Unit": enrolUnitName},
			spans: map[string]time.Duration{"Timer.OnBootSec": time.Minute, "Timer.OnUnitInactiveSec": 5 * time.Minute}},
	} {
		t.Run(r.name, func(t *testing.T) { assertUnitRow(t, cc, r) })
	}
}

func TestRenderUserData_HostsPlatformBootsOpenBaoExternalSecretsAndTraefikBeforeTheClusterRoot(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := testutil.BootDocs(t, cc)

	for _, component := range slices.Sorted(maps.Keys(wantBootTrees)) {
		t.Run(component, func(t *testing.T) {
			file, chart := testutil.OnlyDoc(t, docs, "HelmChart", component)
			base := testutil.YamlMap(t, component, testutil.TestRepoFile(t, "clusterbases/"+component+"/helmchart.yaml"))
			values, baseValues := chartValuesOf(t, component, chart), chartValuesOf(t, "cluster-bases "+component, base)

			testutil.FailIf(t, file >= "10-cluster-root.yaml", "%s boots from %s, which k3s applies after 10-cluster-root.yaml", component, file)
			for _, field := range []string{"chart", "repo", "version", "targetNamespace"} {
				testutil.FailIf(t, testutil.Dig(chart, "spec", field) != testutil.Dig(base, "spec", field), "%s spec.%s = %v, want %v", component, field, testutil.Dig(chart, "spec", field), testutil.Dig(base, "spec", field))
			}
			for k, want := range baseValues {
				testutil.FailIf(t, !reflect.DeepEqual(values[k], want), "%s values.%s = %v, want %v as cluster-bases %s sets it", component, k, values[k], want, wantClusterBasesTag)
			}
			tags := imageTags(values)
			testutil.FailIf(t, len(tags) == 0, "%s's values set no image tag", component)
			for _, tag := range tags {
				testutil.FailIf(t, !imageByDigest.MatchString(tag), "%s names an image by %q, want a digest", component, tag)
			}
		})
	}
	_, traefik := testutil.OnlyDoc(t, docs, "HelmChart", "traefik")
	testutil.AssertPaths(t, "the booted Traefik", chartValuesOf(t, "traefik", traefik), map[string]any{
		"providers.kubernetesIngress.ingressEndpoint.ip": testutil.FixtureIngressIPv4,
		"ports.websecure.nodePort":                       HTTPSNodePort,
	})
	_, pv := testutil.OnlyDoc(t, docs, "PersistentVolume", "openbao-data")
	testutil.FailIf(t, testutil.Dig(pv, "spec", "local", "path") != wantOpenBaoDataDir, "OpenBao's volume is at %v, want %s", testutil.Dig(pv, "spec", "local", "path"), wantOpenBaoDataDir)
}

func TestRenderUserData_HostsPlatformTakesArgoCDsRepositoryCredentialFromAGitHubApp(t *testing.T) {
	ud, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := testutil.BootDocs(t, cc)

	for _, absent := range []string{"mitstack-repo-token", "cluster-repository-tokens"} {
		testutil.FailIf(t, strings.Contains(cc.AllText(ud), absent), "the user data names %s; want no token refresh against the platform", absent)
	}
	skip := cc.File(t, testutil.BootDir+"/05-cluster-repository.yaml.skip")
	testutil.FailIf(t, skip.Owner != "root:root" || skip.Permissions != "0600", "%s is %s %s, want root:root 0600", skip.Path, skip.Owner, skip.Permissions)

	file, secret := testutil.OnlyDoc(t, docs, "ExternalSecret", "cluster-repository")
	testutil.FailIf(t, path.Join(testutil.BootDir, file) != credentialFile, "the repository credential boots from %s, want %s", file, credentialFile)
	testutil.AssertPaths(t, "ExternalSecret cluster-repository", secret, map[string]any{
		"metadata.namespace":                 "argocd",
		"spec.target.name":                   "cluster-repository",
		"spec.target.template.data.url":      testutil.FixtureRepoURL,
		"spec.target.template.data.username": "x-access-token",
		"spec.target.template.data.password": "{{ .token }}",
	})
	testutil.FailIf(t, testutil.Dig(secret, "spec", "target", "template", "metadata", "labels", "argocd.argoproj.io/secret-type") != "repository", "the Secret carries no Argo CD repository label")
	from, _ := testutil.Dig(secret, "spec", "dataFrom").([]any)
	testutil.FatalIf(t, len(from) != 1, "spec.dataFrom has %d entries, want the GitHub generator alone", len(from))
	testutil.FailIf(t, testutil.Dig(from[0], "sourceRef", "generatorRef", "kind") != "GithubAccessToken", "the token comes from %v, want External Secrets' GitHub generator", testutil.Dig(from[0], "sourceRef", "generatorRef", "kind"))

	_, generator := testutil.OnlyDoc(t, docs, "GithubAccessToken", fmt.Sprint(testutil.Dig(from[0], "sourceRef", "generatorRef", "name")))
	testutil.AssertPaths(t, "the GitHub generator", generator, map[string]any{
		"metadata.namespace":                 "argocd",
		"spec.appID":                         testutil.FixtureGitHubAppID,
		"spec.installID":                     testutil.FixtureInstallationID,
		"spec.auth.privateKey.secretRef.key": "private-key",
	})
	testutil.FailIf(t, !slices.Equal(stringsOf(t, "spec.repositories", testutil.Dig(generator, "spec", "repositories")), []string{testutil.FixtureRepoName}), "the token reads %v, want only %s", testutil.Dig(generator, "spec", "repositories"), testutil.FixtureRepoName)

	_, key := testutil.OnlyDoc(t, docs, "ExternalSecret", fmt.Sprint(testutil.Dig(generator, "spec", "auth", "privateKey", "secretRef", "name")))
	data, _ := testutil.Dig(key, "spec", "data").([]any)
	testutil.FatalIf(t, len(data) != 1, "the App key's ExternalSecret copies %d values, want one", len(data))
	testutil.AssertPaths(t, "the App key's source", data[0].(map[string]any), map[string]any{"secretKey": "private-key", "remoteRef.key": "argocd/github-app", "remoteRef.property": "private-key"})
	_, store := testutil.OnlyDoc(t, docs, "SecretStore", fmt.Sprint(testutil.Dig(key, "spec", "secretStoreRef", "name")))
	testutil.AssertPaths(t, "the OpenBao store", store, map[string]any{
		"metadata.namespace":                            "argocd",
		"spec.provider.vault.server":                    "https://openbao.openbao.svc:8200",
		"spec.provider.vault.caProvider.type":           "ConfigMap",
		"spec.provider.vault.caProvider.name":           "openbao-ca",
		"spec.provider.vault.caProvider.key":            "ca.crt",
		"spec.provider.vault.path":                      "kv",
		"spec.provider.vault.version":                   "v2",
		"spec.provider.vault.auth.kubernetes.mountPath": "kubernetes",
		"spec.provider.vault.auth.kubernetes.role":      "argocd",
	})
}

func TestRenderUserData_HostsPlatformServesOpenBaoOverTLSAloneFromACertificateTheClusterAuthorityRenews(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := testutil.BootDocs(t, cc)

	_, chart := testutil.OnlyDoc(t, docs, "HelmChart", "openbao")
	values := chartValuesOf(t, "openbao", chart)
	config := fmt.Sprint(testutil.Dig(values, "server", "standalone", "config"))
	file, serving := testutil.OnlyDoc(t, docs, "Certificate", "openbao-tls")
	_, authority := testutil.OnlyDoc(t, docs, "Certificate", "openbao-ca")
	_, issuer := testutil.OnlyDoc(t, docs, "Issuer", "openbao-ca")
	_, bundle := testutil.OnlyDoc(t, docs, "Bundle", "openbao-ca")

	block := listenerBlockRe.FindStringSubmatch(config)
	testutil.FatalIf(t, block == nil, "OpenBao's configuration holds no tcp listener:\n%s", config)
	listener := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(block[1]), "\n") {
		key, value, _ := strings.Cut(line, "=")
		listener[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	testutil.FailIf(t, !reflect.DeepEqual(listener, map[string]string{"address": "[::]:8200", "cluster_address": "[::]:8201",
		"tls_cert_file": "/openbao/tls/tls.crt", "tls_key_file": "/openbao/tls/tls.key", "tls_min_version": "tls13"}),
		"OpenBao's tcp listener sets %v, want TLS 1.3 alone on 8200 from the certificate and key in /openbao/tls", listener)
	testutil.FailIf(t, !strings.Contains(fmt.Sprint(testutil.Dig(values, "server", "volumes")), "secretName:openbao-tls"), "OpenBao mounts %v, want the Secret openbao-tls the certificate is kept in", testutil.Dig(values, "server", "volumes"))
	testutil.FailIf(t, file >= "03-cluster-repository.yaml", "the certificate boots from %s, after the store that reads OpenBao over TLS", file)
	testutil.AssertPaths(t, "the serving certificate", serving, map[string]any{
		"metadata.namespace":  "openbao",
		"spec.secretName":     "openbao-tls",
		"spec.issuerRef.kind": "Issuer",
		"spec.issuerRef.name": testutil.Dig(issuer, "metadata", "name"),
	})
	testutil.FailIf(t, !slices.Contains(stringsOf(t, "spec.dnsNames", testutil.Dig(serving, "spec", "dnsNames")), "openbao.openbao.svc"), "the certificate names %v, want openbao.openbao.svc", testutil.Dig(serving, "spec", "dnsNames"))
	lifetime, err := time.ParseDuration(fmt.Sprint(testutil.Dig(serving, "spec", "duration")))
	testutil.FatalIf(t, err != nil, "the certificate's duration: %v", err)
	before, err := time.ParseDuration(fmt.Sprint(testutil.Dig(serving, "spec", "renewBefore")))
	testutil.FailIf(t, err != nil || before <= 0 || before >= lifetime, "the certificate renews %v before its %v lifetime ends, want a renewal inside it", testutil.Dig(serving, "spec", "renewBefore"), lifetime)
	testutil.AssertPaths(t, "the authority", authority, map[string]any{
		"metadata.namespace":             "openbao",
		"spec.isCA":                      true,
		"spec.privateKey.rotationPolicy": "Never",
		"spec.secretName":                testutil.Dig(issuer, "spec", "ca", "secretName"),
		"spec.issuerRef.kind":            "Issuer",
	})
	testutil.FailIf(t, testutil.Dig(issuer, "metadata", "namespace") != "openbao", "the authority signs from namespace %v, want openbao alone", testutil.Dig(issuer, "metadata", "namespace"))
	sources, _ := testutil.Dig(bundle, "spec", "sources").([]any)
	testutil.FatalIf(t, len(sources) != 1, "the Bundle copies %d sources, want the authority alone", len(sources))
	testutil.FailIf(t, testutil.Dig(sources[0], "secret", "name") != testutil.Dig(authority, "spec", "secretName") || testutil.Dig(bundle, "spec", "target", "configMap", "key") != "ca.crt",
		"the Bundle copies %v into %v, want the authority's Secret into the ConfigMap key ca.crt", sources[0], testutil.Dig(bundle, "spec", "target"))
	reload, _ := testutil.Dig(values, "server", "extraContainers").([]any)
	testutil.FailIf(t, testutil.Dig(values, "server", "shareProcessNamespace") != true || len(reload) != 1 || !strings.Contains(fmt.Sprint(testutil.Dig(reload[0], "volumeMounts")), "mountPath:/openbao/tls"),
		"OpenBao's pod runs %v with shareProcessNamespace %v, want one container that reads the renewed certificate and signals OpenBao", reload, testutil.Dig(values, "server", "shareProcessNamespace"))
}

func TestRenderUserData_HostsPlatformBootsTheCertManagerEveryClusterRuns(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())

	_, chart := testutil.OnlyDoc(t, testutil.BootDocs(t, cc), "HelmChart", "cert-manager")

	version := PinnedVersions.CertManagerChartVersion
	testutil.FailIf(t, testutil.Dig(chart, "spec", "version") != version, "the booted cert-manager is %v, want %s, the version every cluster runs", testutil.Dig(chart, "spec", "version"), version)
	testutil.FailIf(t, testutil.Dig(chartValuesOf(t, "cert-manager", chart), "acmesolver", "image", "digest") != acmesolverDigests[version],
		"the booted cert-manager runs the HTTP-01 solver by %v, want %s, the one digest the admission policy admits", testutil.Dig(chartValuesOf(t, "cert-manager", chart), "acmesolver", "image", "digest"), acmesolverDigests[version])
}

// mountsOpenBaoCA reports whether pod's one container reads the ConfigMap openbao-ca read-only at wantOpenBaoCADir.
func mountsOpenBaoCA(pod any) bool {
	volumes, _ := testutil.Dig(pod, "spec", "volumes").([]any)
	containers, _ := testutil.Dig(pod, "spec", "containers").([]any)
	if len(containers) != 1 {
		return false
	}
	mounts, _ := testutil.Dig(containers[0], "volumeMounts").([]any)
	for _, v := range volumes {
		for _, m := range mounts {
			if testutil.Dig(v, "configMap", "name") == "openbao-ca" && testutil.Dig(m, "name") == testutil.Dig(v, "name") && testutil.Dig(m, "mountPath") == wantOpenBaoCADir && testutil.Dig(m, "readOnly") == true {
				return true
			}
		}
	}
	return false
}

func TestRenderUserData_HostsPlatformWritesTheSealKeyToOneRootOnlyFile(t *testing.T) {
	ud, cc := renderCC(t, hostsPlatformRenderInputs())

	f := cc.File(t, testutil.SealKeyFile)

	testutil.FailIf(t, f.Owner != "root:root" || f.Permissions != "0600", "%s is %s %s, want root:root 0600", f.Path, f.Owner, f.Permissions)
	testutil.FailIf(t, testutil.SealKeyOf(t, cc) != testutil.FixtureSealKey, "%s holds another key than the one rendered", f.Path)
	testutil.FailIf(t, strings.Count(ud, testutil.FixtureSealKey) != 1, "the seal key appears %d times in the user data, want only in %s", strings.Count(ud, testutil.FixtureSealKey), testutil.SealKeyFile)
}

func TestRenderUserData_HostsPlatformRefusesAnInputOutOfShape(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*HostsPlatformInputs)
	}{
		{"a seal key that is not 64 hex characters", func(h *HostsPlatformInputs) { h.SealKey = testutil.FixtureSealKey[:63] }},
		{"an App id that is not digits", func(h *HostsPlatformInputs) { h.AppID = "12a" }},
		{"an empty installation id", func(h *HostsPlatformInputs) { h.InstallationID = "" }},
		{"a public address that is not dotted IPv4", func(h *HostsPlatformInputs) { h.PublicIPv4 = "203.0.113.010" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := hostsPlatformRenderInputs()
			c.mutate(in.HostsPlatform)

			_, err := RenderUserData(in)

			testutil.FailIf(t, err == nil, "RenderUserData accepted %s", c.name)
		})
	}
}

func TestSeed_HostsPlatformAdoptsTheBootedChartsAndLeavesArgoCDsCredentialToExternalSecrets(t *testing.T) {
	in := hostsPlatformRenderInputs()
	seed, err := RenderSeed(in.Versions, in.HostsPlatform.PublicIPv4, in.ClusterRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)

	err = HostsPlatformSeed(seed, in.HostsPlatform.PublicIPv4)

	testutil.FatalIf(t, err != nil, "HostsPlatformSeed: %v", err)
	_, cc := renderCC(t, in)
	boot := testutil.BootDocs(t, cc)

	for _, component := range slices.Sorted(maps.Keys(wantBootTrees)) {
		t.Run(component, func(t *testing.T) {
			content, ok := seed["cluster/"+component+".yaml"]
			testutil.FatalIf(t, !ok, "the seed holds no cluster/%s.yaml", component)
			_, chart := testutil.OnlyDoc(t, boot, "HelmChart", component)
			testutil.AssertPaths(t, "the "+component+" Application", testutil.YamlMap(t, component, content), map[string]any{
				"spec.source.chart":          testutil.Dig(chart, "spec", "chart"),
				"spec.source.repoURL":        testutil.Dig(chart, "spec", "repo"),
				"spec.source.targetRevision": testutil.Dig(chart, "spec", "version"),
				"spec.source.helm.values":    testutil.Dig(chart, "spec", "valuesContent"),
				"spec.destination.namespace": testutil.Dig(chart, "spec", "targetNamespace"),
			})
		})
	}
	tls := testutil.TestRepoFile(t, "clusterbases/openbao/tls.yaml")
	testutil.FailIf(t, !reflect.DeepEqual(testutil.YamlDocs(t, seedOpenBaoTLSPath, seed[seedOpenBaoTLSPath]), testutil.YamlDocs(t, "clusterbases/openbao/tls.yaml", tls)),
		"the seed's %s is not cluster-bases' openbao/tls.yaml, so Argo CD would not own the authority k3s booted", seedOpenBaoTLSPath)
	var env []string
	var reachesOpenBao bool
	for _, d := range testutil.YamlDocs(t, "cluster/node-agent.yaml", seed["cluster/node-agent.yaml"]) {
		if d["kind"] == "CiliumNetworkPolicy" {
			egress, _ := testutil.Dig(d, "spec", "egress").([]any)
			for _, rule := range egress {
				to, _ := testutil.Dig(rule, "toEndpoints").([]any)
				ports := fmt.Sprint(testutil.Dig(rule, "toPorts"))
				reachesOpenBao = reachesOpenBao || len(to) == 1 && testutil.Dig(to[0], "matchLabels", "k8s:io.kubernetes.pod.namespace") == "openbao" && strings.Contains(ports, "8200")
			}
		}
		if testutil.Dig(d, "metadata", "name") != "mitstack-repo-token" {
			continue
		}
		switch d["kind"] {
		case "CronJob":
			containers, _ := testutil.Dig(d, "spec", "jobTemplate", "spec", "template", "spec", "containers").([]any)
			vars, _ := testutil.Dig(containers[0], "env").([]any)
			for _, v := range vars {
				env = append(env, fmt.Sprintf("%v=%v", testutil.Dig(v, "name"), testutil.Dig(v, "value")))
			}
		case "Role":
			testutil.FailIf(t, strings.Contains(fmt.Sprint(d["rules"]), "cluster-repository"), "the refresh's Role still grants a patch of cluster-repository: %v", d["rules"])
		}
	}
	testutil.FailIf(t, !slices.Contains(env, patchClusterRepositoryEnv+"=false"), "the refresh runs with %v, want %s=false", env, patchClusterRepositoryEnv)
	testutil.FailIf(t, !reachesOpenBao, "mitstack-node's egress policy admits no traffic to OpenBao on 8200, so the boot Job and the App key's writer would be cut off once Argo CD syncs it")
}

const (
	seedOpenBaoTLSPath = "cluster/openbao-tls.yaml"
)
