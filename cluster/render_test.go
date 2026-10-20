package cluster

// render_test.go pins the cloud-init user data RenderUserData produces from fixed inputs.

import (
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

func fixtureRenderInputs() UserDataInputs {
	return UserDataInputs{
		SubscriptionID: testutil.FixtureSubID,
		IssuerURL:      testutil.IssuerURLFor(testutil.FixtureBucket, testutil.FixtureSubID),
		ClusterRepoURL: testutil.FixtureRepoURL,
		EnrolmentToken: testutil.FixtureEnrolmentToken,
		Versions:       PinnedVersions,
	}
}

func renderFixture(t *testing.T) (string, testutil.CloudConfig) {
	t.Helper()
	ud := renderOK(t, fixtureRenderInputs())
	return ud, testutil.ParseUserData(t, ud)
}

func TestPinnedVersions_AreTheReviewedPins(t *testing.T) {
	want := Versions{
		K3sVersion:         "v1.36.3+k3s1",
		K3sSHA256:          "2f98a9f8fe5782479ee2d54e70a1b10a7f6fd4cae8d38ed3098452dc6eed76b5",
		K3sInstallerCommit: "2d0f82fa2f933cd227fe38e1482558ce4769f464",
		K3sInstallerSHA256: "ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b",
		CiliumVersion:      "1.19.3",
		// argo-cd chart 10.9.7 runs Argo CD v3.5.4, the first v3.5 release patched against GHSA-j6cw-g6p4-7hch.
		ArgoCDChartVersion: "10.9.7",
		// kured chart 6.1.0 runs kured 1.23.0.
		KuredChartVersion:              "6.1.0",
		SystemUpgradeControllerVersion: "v0.20.2",
		// traefik chart 41.6.1 runs Traefik v3.7.13.
		TraefikChartVersion:     "41.6.1",
		CertManagerChartVersion: "v1.21.2",
		// kyverno chart 3.9.1 runs Kyverno v1.19.1.
		KyvernoChartVersion: "3.9.1",
	}
	testutil.FailIf(t, PinnedVersions != want, "PinnedVersions = %+v\nwant           %+v", PinnedVersions, want)
}

func TestRenderUserData_K3sConfigDisablesFlannelAndNetworkPolicyAndSetsTheIssuer(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, "/etc/rancher/k3s/config.yaml")
	testutil.FailIf(t, f.Permissions != "0600", "/etc/rancher/k3s/config.yaml permissions = %q, want 0600", f.Permissions)
	issuer := testutil.IssuerURLFor(testutil.FixtureBucket, testutil.FixtureSubID)
	testutil.AssertValues(t, "k3s config.yaml", testutil.YamlMap(t, "k3s config.yaml", f.Content), map[string]any{
		"cluster-init":           true,
		"disable":                []any{"local-storage", "traefik"},
		"flannel-backend":        "none",
		"disable-network-policy": true,
		"disable-kube-proxy":     false,
		"cluster-cidr":           "10.42.0.0/16",
		"service-cidr":           "10.43.0.0/16",
		"cluster-dns":            "10.43.0.10",
		"kubelet-arg": []any{
			"cloud-provider=external",
			"volume-plugin-dir=/var/lib/kubelet/volumeplugins",
			"kube-reserved=cpu=250m,memory=1500Mi,ephemeral-storage=1Gi",
			"system-reserved=cpu=250m,memory=300Mi",
		},
		"kube-controller-manager-arg": []any{"flex-volume-plugin-dir=/var/lib/kubelet/volumeplugins"},
		"kube-apiserver-arg": []any{
			"service-account-issuer=" + issuer,
			"service-account-jwks-uri=" + issuer + "/openid/v1/jwks",
		},
		"secrets-encryption": true,
	})
}

func TestRenderUserData_CiliumHelmChartCarriesHubbleAndTheBriefsValues(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, "/var/lib/rancher/k3s/server/manifests/cilium.yaml")
	chart := testutil.YamlMap(t, "cilium.yaml", f.Content)

	testutil.AssertPaths(t, "cilium HelmChart", chart, map[string]any{
		"apiVersion": "helm.cattle.io/v1", "kind": "HelmChart", "metadata.name": "cilium", "metadata.namespace": "kube-system",
		"spec.chart": "cilium", "spec.repo": "https://helm.cilium.io/", "spec.version": "1.19.3", "spec.targetNamespace": "kube-system", "spec.bootstrap": true,
	})

	values := chartValuesOf(t, "cilium HelmChart", chart)

	testutil.AssertValues(t, "cilium valuesContent", values, map[string]any{
		"ipam":                 map[string]any{"mode": "kubernetes"},
		"k8s":                  map[string]any{"requireIPv4PodCIDR": true},
		"ipv4":                 map[string]any{"enabled": true},
		"ipv6":                 map[string]any{"enabled": false},
		"kubeProxyReplacement": false,
		"k8sServiceHost":       "127.0.0.1",
		"k8sServicePort":       "6444",
		"routingMode":          "tunnel",
		"rollOutCiliumPods":    true,
		"endpointRoutes":       map[string]any{"enabled": true},
		"loadBalancer":         map[string]any{"acceleration": "best-effort"},
		"bpf":                  map[string]any{"masquerade": false},
		"hubble": map[string]any{
			"relay": map[string]any{"enabled": true},
			"ui":    map[string]any{"enabled": true},
		},
		"MTU": 1450,
		"operator": map[string]any{
			"replicas": 1,
			"updateStrategy": map[string]any{
				"rollingUpdate": map[string]any{"maxSurge": 0, "maxUnavailable": 1},
			},
		},
	})
}

func assertOneOperatorRollingInPlace(t *testing.T, what string, values map[string]any) {
	t.Helper()
	for _, v := range []struct {
		path []string
		want any
	}{
		{[]string{"operator", "replicas"}, 1},
		{[]string{"operator", "updateStrategy", "rollingUpdate", "maxSurge"}, 0},
		{[]string{"operator", "updateStrategy", "rollingUpdate", "maxUnavailable"}, 1},
	} {
		got := testutil.Dig(values, v.path...)
		testutil.FailIf(t, !reflect.DeepEqual(got, v.want), "%s: %s = %#v, want %#v: the operator runs on the host network and one node cannot schedule a second hostNetwork operator pod, so a second replica or a surge stays Pending and a rollout never completes",
			what, strings.Join(v.path, "."), got, v.want)
	}
}

func assertNoCredentialKeys(t *testing.T, what string, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		testutil.FailIf(t, x["kind"] == "Secret", "%s declares a Secret", what)
		for k, child := range x {
			lk := strings.ToLower(k)
			for _, bad := range []string{"password", "token", "privatekey", "secret", "credential", "bearer"} {
				testutil.FailIf(t, strings.Contains(lk, bad), "%s carries a credential-shaped key %q", what, k)
			}
			assertNoCredentialKeys(t, what+"."+k, child)
		}
	case []any:
		for i, child := range x {
			assertNoCredentialKeys(t, fmt.Sprintf("%s[%d]", what, i), child)
		}
	}
}

func TestRenderUserData_ArgoCDBootstrapInstallsTheChartWithNoCredential(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, "/var/lib/rancher/k3s/server/manifests/00-argocd-bootstrap.yaml")
	docs := testutil.YamlDocs(t, "00-argocd-bootstrap.yaml", f.Content)
	testutil.FatalIf(t, len(docs) != 2, "00-argocd-bootstrap.yaml holds %d documents, want the argocd Namespace and the argocd HelmChart", len(docs))

	var ns, chart map[string]any
	for _, d := range docs {
		switch d["kind"] {
		case "Namespace":
			ns = d
		case "HelmChart":
			chart = d
		}
	}
	testutil.FailIf(t, ns == nil || testutil.Dig(ns, "metadata", "name") != "argocd" || ns["apiVersion"] != "v1", "want a v1 Namespace named argocd, got %v", ns)
	testutil.FatalIf(t, chart == nil, "no HelmChart document in 00-argocd-bootstrap.yaml")
	testutil.AssertPaths(t, "argocd HelmChart", chart, map[string]any{
		"apiVersion": "helm.cattle.io/v1", "metadata.name": "argocd", "metadata.namespace": "kube-system", "spec.chart": "argo-cd",
		"spec.repo": "https://argoproj.github.io/argo-helm", "spec.version": "10.9.7", "spec.targetNamespace": "argocd",
	})
	values := chartValuesOf(t, "argocd HelmChart", chart)
	testutil.AssertValues(t, "argocd valuesContent", values, map[string]any{
		"dex":           map[string]any{"enabled": false},
		"notifications": map[string]any{"cm": map[string]any{"create": false}, "secret": map[string]any{"create": false}},
		"configs":       map[string]any{"cm": map[string]any{argoCDApplicationHealthKey: wantApplicationHealthCheck}},
	})

	for i, d := range docs {
		assertNoCredentialKeys(t, fmt.Sprintf("00-argocd-bootstrap.yaml[%d]", i), d)
	}
	// notifications.secret is the chart's switch that stops it creating
	// argocd-notifications-secret, pinned to create: false above, so it is the
	// one secret-named key the walk leaves out.
	walked := maps.Clone(values)
	if n, ok := values["notifications"].(map[string]any); ok {
		n = maps.Clone(n)
		if reflect.DeepEqual(n["secret"], map[string]any{"create": false}) {
			delete(n, "secret")
		}
		walked["notifications"] = n
	}
	assertNoCredentialKeys(t, "argocd valuesContent", walked)
}

func TestRenderUserData_ClusterRootApplicationSyncsTheClusterRepository(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, "/var/lib/rancher/k3s/server/manifests/10-cluster-root.yaml")
	app := testutil.YamlMap(t, "10-cluster-root.yaml", f.Content)

	testutil.AssertPaths(t, "cluster-root Application", app, map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata.name": "cluster-root", "metadata.namespace": "argocd", "spec.project": "default",
		"spec.source":                     map[string]any{"repoURL": testutil.FixtureRepoURL, "path": "cluster", "targetRevision": "HEAD"},
		"spec.destination":                map[string]any{"server": "https://kubernetes.default.svc", "namespace": "argocd"},
		"spec.syncPolicy.automated.prune": true, "spec.syncPolicy.automated.selfHeal": true,
	})
	assertNoCredentialKeys(t, "10-cluster-root.yaml", app)
}

func TestRenderUserData_EnrolmentEnvCarriesTheTokenSubscriptionAndRepositoryURL(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, "/etc/mitstack/enrolment.env")
	testutil.FailIf(t, f.Permissions != "0600", "/etc/mitstack/enrolment.env permissions = %q, want 0600", f.Permissions)
	want := map[string]string{
		"MITSTACK_ENROLMENT_TOKEN": testutil.FixtureEnrolmentToken,
		"MITSTACK_SUBSCRIPTION_ID": testutil.FixtureSubID,
		"MITSTACK_REPOSITORY_URL":  testutil.FixtureRepoURL,
	}
	got := testutil.EnrolmentEnv(t, cc)
	testutil.FailIf(t, !maps.Equal(got, want), "enrolment.env = %v, want exactly %v", got, want)
}

func assertRootScript(t *testing.T, what string, f testutil.CloudFile) {
	t.Helper()
	testutil.FailIf(t, f.Permissions != "0700", "%s %s permissions = %q, want 0700", what, f.Path, f.Permissions)
	testutil.FailIf(t, f.Owner != "" && f.Owner != "root" && f.Owner != "root:root", "%s %s owner = %q, want root", what, f.Path, f.Owner)
}

func TestRenderUserData_VerifiedInstallerPinsTheInstallerAndBinaryDigestsAndLeavesStartingK3sToTheChain(t *testing.T) {
	_, cc := renderFixture(t)
	body := cc.Installer(t).Content
	v := PinnedVersions

	for _, needle := range []string{
		"https://raw.githubusercontent.com/k3s-io/k3s/" + v.K3sInstallerCommit + "/install.sh",
		"https://github.com/k3s-io/k3s/releases/download/v1.36.3%2Bk3s1/k3s",
		v.K3sInstallerSHA256,
		v.K3sSHA256,
		"sha256sum",
		"/usr/local/bin/k3s",
	} {
		testutil.FailIf(t, !strings.Contains(body, needle), "the verified installer does not contain %q", needle)
	}
	for _, env := range []string{
		`INSTALL_K3S_SKIP_DOWNLOAD=["']?true["']?`,
		`INSTALL_K3S_VERSION=["']?v1\.36\.3\+k3s1["']?`,
		`INSTALL_K3S_EXEC=["']?server["']?`,
		`INSTALL_K3S_SKIP_START=["']?true["']?`,
	} {
		testutil.FailIf(t, !regexp.MustCompile(env).MatchString(body), "the verified installer does not run install.sh with %s", env)
	}
	testutil.FailIf(t, strings.Contains(body, "get.k3s.io"), "the verified installer fetches the unpinned get.k3s.io script")
}

func TestRenderUserData_EveryVersionInputReachesTheDocument(t *testing.T) {
	recordACMESolverDigest(t, "v1.22.0")
	in := fixtureRenderInputs()
	in.Versions = Versions{
		K3sVersion:         "v1.37.1+k3s1",
		K3sSHA256:          strings.Repeat("a", 64),
		K3sInstallerCommit: strings.Repeat("b", 40),
		K3sInstallerSHA256: strings.Repeat("c", 64),
		CiliumVersion:      "1.20.0",
		ArgoCDChartVersion: "11.0.0",
		// These five reach the cluster repository's seed, not the user data;
		// clusterseed_test.go follows them there.
		KuredChartVersion:              "6.2.0",
		SystemUpgradeControllerVersion: "v0.21.0",
		TraefikChartVersion:            "41.7.0",
		CertManagerChartVersion:        "v1.22.0",
		KyvernoChartVersion:            "3.10.0",
	}
	_, cc := renderCC(t, in)

	installer := cc.Installer(t).Content
	for _, needle := range []string{
		"https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/k3s",
		strings.Repeat("a", 64),
		"https://raw.githubusercontent.com/k3s-io/k3s/" + strings.Repeat("b", 40) + "/install.sh",
		strings.Repeat("c", 64),
	} {
		testutil.FailIf(t, !strings.Contains(installer, needle), "the installer rendered with changed versions does not contain %q", needle)
	}
	if !regexp.MustCompile(`INSTALL_K3S_VERSION=["']?v1\.37\.1\+k3s1["']?`).MatchString(installer) {
		t.Error("the installer does not install the K3sVersion it was rendered with")
	}

	cilium := testutil.YamlMap(t, "cilium.yaml", cc.File(t, "/var/lib/rancher/k3s/server/manifests/cilium.yaml").Content)
	got := testutil.Dig(cilium, "spec", "version")
	testutil.FailIf(t, got != "1.20.0", "cilium chart version = %#v, want the CiliumVersion input 1.20.0", got)
	for _, d := range testutil.YamlDocs(t, "00-argocd-bootstrap.yaml", cc.File(t, "/var/lib/rancher/k3s/server/manifests/00-argocd-bootstrap.yaml").Content) {
		if d["kind"] == "HelmChart" {
			got := testutil.Dig(d, "spec", "version")
			testutil.FailIf(t, got != "11.0.0", "argo-cd chart version = %#v, want the ArgoCDChartVersion input 11.0.0", got)
		}
	}
}

func TestRenderUserData_CarriesNoCredentialButTheEnrolmentToken(t *testing.T) {
	ud, cc := renderFixture(t)
	testutil.AssertNoCredentialShapes(t, "the rendered user data", cc.AllText(ud))
	for _, d := range testutil.YamlDocs(t, "the user data", ud) {
		testutil.FailIf(t, d["kind"] == "Config", "the user data is itself a kubeconfig document")
	}

	var holders []string
	for _, f := range cc.WriteFiles {
		if strings.Contains(f.Content, testutil.FixtureEnrolmentToken) {
			holders = append(holders, f.Path)
		}
	}
	testutil.FailIf(t, !slices.Equal(holders, []string{"/etc/mitstack/enrolment.env"}), "the enrolment token is written to %v, want only /etc/mitstack/enrolment.env", holders)
	testutil.FailIf(t, strings.Contains(cc.RuncmdText(), testutil.FixtureEnrolmentToken), "runcmd carries the enrolment token")
}

// keptOnTheHost is every file ADR 0087 keeps in the user data: node naming, the k3s install, the metadata guard,
// enrolment and the host's own patching settings.
var keptOnTheHost = []string{
	"/etc/rancher/k3s/config.yaml",
	"/var/lib/rancher/k3s/server/manifests/cilium.yaml",
	"/var/lib/rancher/k3s/server/manifests/00-argocd-bootstrap.yaml",
	"/var/lib/rancher/k3s/server/manifests/10-cluster-root.yaml",
	"/etc/mitstack/enrolment.env",
	"/etc/mitstack/metadata-guard.nft",
	"/usr/local/sbin/mitstack-hcloud-node",
	"/usr/local/sbin/mitstack-enrol",
	"/usr/local/sbin/mitstack-install-k3s",
	"/etc/systemd/system/mitstack-enrol.service",
	"/etc/systemd/system/k3s.service.d/10-mitstack-enrolment.conf",
	"/etc/systemd/system/mitstack-metadata-guard.service",
	"/etc/systemd/system/k3s.service.d/20-mitstack-metadata-guard.conf",
	"/etc/systemd/system/apt-daily-upgrade.timer.d/10-mitstack-maintenance-window.conf",
	"/etc/apt/apt.conf.d/52mitstack-unattended-upgrades",
}

func TestRenderUserData_WritesOnlyTheFilesTheDecisionRecordKeepsOnTheHost(t *testing.T) {
	_, cc := renderCC(t, longestRenderInputs())

	var paths []string
	for _, f := range cc.WriteFiles {
		paths = append(paths, f.Path)
	}

	testutil.FailIf(t, !slices.Equal(slices.Sorted(slices.Values(paths)), slices.Sorted(slices.Values(keptOnTheHost))), "the user data writes %q\nwant only %q", paths, keptOnTheHost)
}

func TestRenderUserData_TheLongestRenderingIsAtMost19000Bytes(t *testing.T) {
	ud := renderOK(t, longestRenderInputs())

	testutil.FailIf(t, len(ud) > 19000, "the longest user data is %d bytes, want at most 19,000 now it carries only the bootstrap", len(ud))
}

func TestRenderUserData_RuncmdIsOneChainInTheOrderThatKeepsK3sBehindEveryGuard(t *testing.T) {
	_, cc := renderFixture(t)
	node, enrol, installer := cc.NodeScript(t), cc.EnrolScript(t), cc.Installer(t)
	assertRootScript(t, "the node script", node)
	assertRootScript(t, "the verified installer", installer)

	steps := strings.Split(runcmdChain(t, cc), " && ")

	want := []string{
		sshMask,
		"systemctl daemon-reload",
		metadataGuardStart,
		node.Path,
		"systemctl start " + enrolUnitName,
		autoUpgradeEnable,
		aptDailyRefreshNow,
		installer.Path,
		"systemctl enable --now k3s",
	}
	testutil.FailIf(t, !slices.Equal(steps, want), "runcmd[0] = %q\nwant %q: SSH masked first; the guard started once systemd has read its unit and before any pod can run; the patching units enabled and the lists refreshed without blocking before k3s is installed; a failed step stops k3s", strings.Join(steps, " && "), strings.Join(want, " && "))
	testutil.FailIf(t, strings.Contains(strings.Join(steps, " "), enrol.Path), "runcmd invokes the enrol script %s directly, want it run only by %s", enrol.Path, enrolUnitName)
}

func runcmdChain(t *testing.T, cc testutil.CloudConfig) string {
	t.Helper()
	testutil.FatalIf(t, len(cc.RunCmd) != 1, "runcmd has %d entries, want exactly one chained entry: %#v", len(cc.RunCmd), cc.RunCmd)
	entry, ok := cc.RunCmd[0].(string)
	testutil.FatalIf(t, !ok, "runcmd[0] is %T, want a string the shell runs as one && chain", cc.RunCmd[0])
	return entry
}

const (
	sshMask                 = "systemctl mask --now ssh.service ssh.socket"
	metadataGuardUnitName   = "mitstack-metadata-guard.service"
	metadataGuardUnitPath   = systemdDir + "/" + metadataGuardUnitName
	metadataGuardRulesPath  = "/etc/mitstack/metadata-guard.nft"
	metadataGuardTable      = "mitstack_metadata_guard"
	k3sMetadataGuardDropIn  = systemdDir + "/k3s.service.d/20-mitstack-metadata-guard.conf"
	metadataGuardStart      = "systemctl enable --now " + metadataGuardUnitName
	metadataServiceAddress  = "169.254.169.254"
	metadataGuardDropRule   = "ip daddr " + metadataServiceAddress + " counter drop"
	metadataGuardChainHook  = "type filter hook forward priority -10"
	metadataGuardNftCommand = "/usr/sbin/nft -f " + metadataGuardRulesPath
)

type nftStatement struct {
	words    []string
	hasBlock bool
	block    []nftStatement
}

func (s nftStatement) text() string { return strings.Join(s.words, " ") }

func parseNft(t *testing.T, content string) []nftStatement {
	t.Helper()
	var toks []string
	var word strings.Builder
	flushWord := func() {
		if word.Len() > 0 {
			toks = append(toks, word.String())
			word.Reset()
		}
	}
	inComment := false
	for _, r := range content {
		switch {
		case inComment && r != '\n':
		case r == '#':
			flushWord()
			inComment = true
		case r == '\n' || r == ';' || r == '{' || r == '}':
			flushWord()
			inComment = false
			toks = append(toks, string(r))
		case r == ' ' || r == '\t' || r == '\r':
			flushWord()
		default:
			word.WriteRune(r)
		}
	}
	flushWord()
	stmts, rest := parseNftBlock(t, toks, false)
	testutil.FatalIf(t, len(rest) != 0, "%s has an unmatched } before %q", metadataGuardRulesPath, rest)
	return stmts
}

func parseNftBlock(t *testing.T, toks []string, inBlock bool) ([]nftStatement, []string) {
	t.Helper()
	var out []nftStatement
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, nftStatement{words: cur})
			cur = nil
		}
	}
	for len(toks) > 0 {
		tok := toks[0]
		toks = toks[1:]
		switch tok {
		case "\n", ";":
			flush()
		case "{":
			var inner []nftStatement
			inner, toks = parseNftBlock(t, toks, true)
			out = append(out, nftStatement{words: cur, hasBlock: true, block: inner})
			cur = nil
		case "}":
			if !inBlock {
				return out, append([]string{tok}, toks...)
			}
			flush()
			return out, toks
		default:
			cur = append(cur, tok)
		}
	}
	testutil.FatalIf(t, inBlock, "%s leaves a { block unclosed", metadataGuardRulesPath)
	flush()
	return out, nil
}

func isGuardTable(words []string) bool {
	want := []string{"table", "inet", metadataGuardTable}
	return slices.Equal(words, want) || slices.Equal(words, append([]string{"add"}, want...))
}

func TestRenderUserData_MetadataGuardRulesetDropsForwardedTrafficToTheMetadataService(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, metadataGuardRulesPath)
	testutil.FailIf(t, f.Owner != "root:root", "%s owner = %q, want root:root", metadataGuardRulesPath, f.Owner)
	testutil.FailIf(t, f.Permissions != "0600", "%s permissions = %q, want 0600", metadataGuardRulesPath, f.Permissions)
	for _, word := range []string{"flush", "ruleset"} {
		testutil.FailIf(t, slices.Contains(strings.Fields(f.Content), word), "%s says %q, want the guard's own table replaced and nothing else touched:\n%s", metadataGuardRulesPath, word, f.Content)
	}

	top := parseNft(t, f.Content)
	testutil.FatalIf(t, len(top) != 3, "%s holds %d top-level statements, want three: declare the table, delete it, define it:\n%s", metadataGuardRulesPath, len(top), f.Content)
	declare := top[0]
	testutil.FailIf(t, !isGuardTable(declare.words) || len(declare.block) != 0, "%s first statement is %q, want the bare declaration table inet %s, so the delete after it never fails", metadataGuardRulesPath, declare.text(), metadataGuardTable)
	del := top[1]
	testutil.FailIf(t, del.text() != "delete table inet "+metadataGuardTable || del.hasBlock, "%s second statement is %q, want delete table inet %s", metadataGuardRulesPath, del.text(), metadataGuardTable)
	define := top[2]
	testutil.FatalIf(t, !isGuardTable(define.words) || !define.hasBlock, "%s third statement is %q, want table inet %s { ... }", metadataGuardRulesPath, define.text(), metadataGuardTable)
	if len(define.block) != 1 || define.block[0].text() != "chain forward" || !define.block[0].hasBlock {
		var got []string
		for _, s := range define.block {
			got = append(got, s.text())
		}
		t.Fatalf("table inet %s holds %q, want exactly the chain forward { ... }", metadataGuardTable, got)
	}
	var chain []string
	for _, s := range define.block[0].block {
		chain = append(chain, s.text())
	}
	want := []string{metadataGuardChainHook, "policy accept", metadataGuardDropRule}
	testutil.FailIf(t, !slices.Equal(chain, want), "chain forward holds %q, want exactly %q", chain, want)
}

const (
	systemdDir        = "/etc/systemd/system"
	enrolUnitName     = "mitstack-enrol.service"
	enrolUnitPath     = systemdDir + "/" + enrolUnitName
	k3sEnrolDropIn    = systemdDir + "/k3s.service.d/10-mitstack-enrolment.conf"
	enrolmentJSONPath = "/etc/mitstack/enrolment.json"
)

type systemdUnit map[string]map[string][]string

func parseSystemdUnit(t *testing.T, what, content string) systemdUnit {
	t.Helper()
	u := systemdUnit{}
	section := ""
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if u[section] == nil {
				u[section] = map[string][]string{}
			}
			continue
		}
		testutil.FatalIf(t, section == "", "%s line %d %q sits outside any [Section]", what, i+1, line)
		k, v, ok := strings.Cut(line, "=")
		testutil.FatalIf(t, !ok, "%s line %d %q is not Key=Value", what, i+1, line)
		k = strings.TrimSpace(k)
		u[section][k] = append(u[section][k], strings.TrimSpace(v))
	}
	return u
}

func (u systemdUnit) one(t *testing.T, what, section, key string) string {
	t.Helper()
	vals := u[section][key]
	if len(vals) != 1 {
		t.Errorf("%s [%s] assigns %s %d times (%q), want exactly once", what, section, key, len(vals), vals)
		return ""
	}
	return vals[0]
}

func (u systemdUnit) listed(section, key, name string) bool {
	for _, v := range u[section][key] {
		if slices.Contains(strings.Fields(v), name) {
			return true
		}
	}
	return false
}

func systemdSpan(s string) (time.Duration, bool) {
	units := map[string]time.Duration{
		"": time.Second, "s": time.Second, "sec": time.Second, "second": time.Second, "seconds": time.Second,
		"m": time.Minute, "min": time.Minute, "minute": time.Minute, "minutes": time.Minute,
		"h": time.Hour, "hr": time.Hour, "hour": time.Hour, "hours": time.Hour,
	}
	term := regexp.MustCompile(`^([0-9]+)\s*([a-z]*)$`)
	var total time.Duration
	parts := regexp.MustCompile(`[0-9]+\s*[a-z]*`).FindAllString(strings.TrimSpace(s), -1)
	if len(parts) == 0 || strings.Join(parts, "") != strings.Join(strings.Fields(s), "") {
		return 0, false
	}
	for _, p := range parts {
		m := term.FindStringSubmatch(strings.TrimSpace(p))
		unit, ok := units[m[2]]
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, false
		}
		total += time.Duration(n) * unit
	}
	return total, true
}

func renderedUnit(t *testing.T, cc testutil.CloudConfig, path string) systemdUnit {
	t.Helper()
	f := cc.File(t, path)
	testutil.FailIf(t, f.Owner != "" && f.Owner != "root" && f.Owner != "root:root", "%s owner = %q, want root", path, f.Owner)
	return parseSystemdUnit(t, path, f.Content)
}

func TestRenderUserData_RepositoryHTTPSURLIsTheClusterRepoURLInBothPlaces(t *testing.T) {
	const otherOwner = "other-owner"
	in := fixtureRenderInputs()
	in.ClusterRepoURL = "https://github.com/" + otherOwner + "/" + testutil.OtherAppName + "-cluster"
	want := in.ClusterRepoURL
	_, cc := renderCC(t, in)
	app := testutil.YamlMap(t, "10-cluster-root.yaml", cc.File(t, "/var/lib/rancher/k3s/server/manifests/10-cluster-root.yaml").Content)
	got := testutil.Dig(app, "spec", "source", "repoURL")
	testutil.FailIf(t, got != want, "cluster-root repoURL = %#v, want %q", got, want)
	got2 := testutil.EnrolmentEnv(t, cc)["MITSTACK_REPOSITORY_URL"]
	testutil.FailIf(t, got2 != want, "enrolment.env MITSTACK_REPOSITORY_URL = %q, want %q", got2, want)
}

func TestRenderUserData_CarriesNoSSHRepositoryURL(t *testing.T) {
	ud, cc := renderFixture(t)
	text := cc.AllText(ud)
	for _, bad := range []string{"git" + "@github.com:", "sshPrivateKey"} {
		testutil.FailIf(t, strings.Contains(text, bad), "the rendered user data carries %q", bad)
	}
}

func longestRenderInputs() UserDataInputs {
	in := fixtureRenderInputs()
	in.SubscriptionID = "a" + strings.Repeat("b-c_d.", 10) + "0"
	in.SubscriptionID += strings.Repeat("z", 63-len(in.SubscriptionID))
	in.IssuerURL = testutil.IssuerURLFor(testutil.FixtureBucket, in.SubscriptionID)
	in.ClusterRepoURL = "https://github.com/" + strings.Repeat("o", 38) + "9/" + strings.Repeat("r.", 46) + "-cluster"
	return in
}

const (

	// autoUpgradeUnits are the units that patch the OS, which the chain
	// enables and the report asks systemctl is-enabled about.
	autoUpgradeUnits  = "unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer"
	autoUpgradeEnable = "systemctl enable --now " + autoUpgradeUnits
	// aptDailyRefreshNow refreshes the package lists once at first boot,
	// without waiting for it, so a fresh node's lists are current within
	// minutes rather than at apt-daily.timer's next randomised run.
	aptDailyRefreshNow = "systemctl start --no-block apt-daily.service"

	aptDailyUpgradeDropIn   = systemdDir + "/apt-daily-upgrade.timer.d/10-mitstack-maintenance-window.conf"
	unattendedUpgradesConf  = "/etc/apt/apt.conf.d/52mitstack-unattended-upgrades"
	unattendedUpdatesOrigin = "${distro_id}:${distro_codename}-updates"
)

func aptConfStatements(content string) string {
	var b strings.Builder
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func TestRenderUserData_UnattendedUpgradesTakesTheUpdatesPocketAndNeverRebootsItself(t *testing.T) {
	_, cc := renderFixture(t)
	f := cc.File(t, unattendedUpgradesConf)
	testutil.FailIf(t, f.Permissions != "0644", "%s permissions = %q, want 0644", unattendedUpgradesConf, f.Permissions)
	conf := aptConfStatements(f.Content)
	// An origin such as ${distro_id} holds braces inside its quotes, so the
	// block's body skips over quoted strings whole.
	origins := regexp.MustCompile(`(?s)Unattended-Upgrade::Allowed-Origins\s*\{((?:[^}"]|"[^"]*")*)\}\s*;`).FindAllStringSubmatch(conf, -1)
	var listed []string
	for _, m := range origins {
		for _, q := range regexp.MustCompile(`"([^"]*)"\s*;`).FindAllStringSubmatch(m[1], -1) {
			listed = append(listed, q[1])
		}
	}
	testutil.FailIf(t, !slices.Contains(listed, unattendedUpdatesOrigin), "%s adds the origins %q to Unattended-Upgrade::Allowed-Origins, want %q among them:\n%s", unattendedUpgradesConf, listed, unattendedUpdatesOrigin, f.Content)
	reboots := regexp.MustCompile(`Unattended-Upgrade::Automatic-Reboot\s+"([^"]*)"\s*;`).FindAllStringSubmatch(conf, -1)
	testutil.FailIf(t, len(reboots) == 0, "%s does not set Unattended-Upgrade::Automatic-Reboot \"false\":\n%s", unattendedUpgradesConf, f.Content)
	for _, m := range reboots {
		testutil.FailIf(t, m[1] != "false", "%s sets Unattended-Upgrade::Automatic-Reboot %q, want \"false\": kured reboots, inside the window and after a drain", unattendedUpgradesConf, m[1])
	}
}

func TestRenderUserData_ClusterRootCarriesNoRetryPolicy(t *testing.T) {
	for name, inputs := range goldenUserDataInputs {
		t.Run(name, func(t *testing.T) {
			cc := testutil.ParseUserData(t, renderOK(t, inputs()))
			app := testutil.YamlMap(t, "10-cluster-root.yaml", cc.File(t, "/var/lib/rancher/k3s/server/manifests/10-cluster-root.yaml").Content)
			policy, ok := testutil.Dig(app, "spec", "syncPolicy").(map[string]any)
			testutil.FatalIf(t, !ok, "cluster-root spec.syncPolicy is %#v, want a mapping", testutil.Dig(app, "spec", "syncPolicy"))
			retry, present := policy["retry"]
			testutil.FailIf(t, present, "cluster-root spec.syncPolicy.retry = %#v, want no retry key, so a failed first sync stays failed where the node report shows it", retry)
		})
	}
}

// argoCDApplicationHealthKey is the argocd-cm key that restores the health of an Application, which Argo CD stopped assessing in release 1.8.
const argoCDApplicationHealthKey = "resource.customizations.health.argoproj.io_Application"

// wantApplicationHealthCheck is the Lua of Argo CD's health guide in one line: the child's own health, Progressing until it has one.
const wantApplicationHealthCheck = `local h=obj.status and obj.status.health or {} return {status=h.status or "Progressing",message=h.message or ""}`

func applicationHealthCheckIn(t *testing.T, what, values string) any {
	t.Helper()
	return testutil.Dig(testutil.YamlMap(t, what, values), "configs", "cm", argoCDApplicationHealthKey)
}

func TestRenderUserData_BothCopiesOfTheArgoCDValuesAssessEachChildApplicationsHealth(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		chartValues, _ := testutil.Dig(bootstrapHelmCharts(t, v)["argocd"], "spec", "valuesContent").(string)
		got := applicationHealthCheckIn(t, "the bootstrap argocd HelmChart's valuesContent", chartValues)
		testutil.FailIf(t, got != wantApplicationHealthCheck, "the bootstrap argocd HelmChart's valuesContent configs.cm[%q] = %#v, want %q, so cluster-root's first sync waits for each child Application in a wave to be Healthy", argoCDApplicationHealthKey, got, wantApplicationHealthCheck)

		appValues, _ := testutil.Dig(seedApplications(t, v)["argocd"], "spec", "source", "helm", "values").(string)
		got = applicationHealthCheckIn(t, testutil.SeedArgoCDPath+" helm.values", appValues)
		testutil.FailIf(t, got != wantApplicationHealthCheck, "%s helm.values configs.cm[%q] = %#v, want %q, so the self-managed Argo CD keeps the check", testutil.SeedArgoCDPath, argoCDApplicationHealthKey, got, wantApplicationHealthCheck)
	})
}

func TestRenderUserData_RefusesAKuredOrUpgradeControllerPinOutOfShape(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		mutate      func(*Versions)
	}{
		{"an empty kured chart version", "KuredChartVersion", func(v *Versions) { v.KuredChartVersion = "" }},
		{"a kured chart version carrying a second YAML line", "KuredChartVersion", func(v *Versions) { v.KuredChartVersion = "6.1.0\nconfiguration: {}" }},
		{"a kured chart version that is a tag name", "KuredChartVersion", func(v *Versions) { v.KuredChartVersion = "latest" }},
		{"an empty system-upgrade-controller version", "SystemUpgradeControllerVersion", func(v *Versions) { v.SystemUpgradeControllerVersion = "" }},
		{"a system-upgrade-controller version carrying a shell command", "SystemUpgradeControllerVersion", func(v *Versions) { v.SystemUpgradeControllerVersion = "v0.20.2; reboot" }},
		{"a system-upgrade-controller version that is a branch name", "SystemUpgradeControllerVersion", func(v *Versions) { v.SystemUpgradeControllerVersion = "master" }},
		{"a system-upgrade-controller version without the v prefix", "SystemUpgradeControllerVersion", func(v *Versions) { v.SystemUpgradeControllerVersion = "0.20.2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fixtureRenderInputs()
			tc.mutate(&in.Versions)

			_, err := RenderUserData(in)

			value := reflect.ValueOf(in.Versions).FieldByName(tc.field).String()
			testutil.FatalIf(t, err == nil, "RenderUserData rendered with %s = %q, want a refusal", tc.field, value)
			testutil.FailIf(t, !strings.Contains(err.Error(), tc.field), "RenderUserData refused %s = %q with %q, want the error to name %s", tc.field, value, err, tc.field)
		})
	}
}

type unitRow struct {
	name, path, perms string
	one               map[string]string        // "Section.Key" to the value it is assigned exactly once
	listed            []string                 // "Section.Key=name": name is among the units listed
	spans             map[string]time.Duration // "Section.Key" to the time span it is assigned
	assigned          map[string][]string      // "Section.Key" to every value assigned, in order
	timerOf           string                   // the service a timer runs, when it names one
}

func TestRenderUserData_Units(t *testing.T) {
	_, cc := renderFixture(t)
	testutil.FailIf(t, cc.EnrolScript(t).Path != enrolScriptPath, "the enrol script is at %s, want %s", cc.EnrolScript(t).Path, enrolScriptPath)
	rows := []unitRow{
		{name: "enrol runs once, before k3s", path: enrolUnitPath, listed: []string{"Unit.Before=k3s.service"}, one: map[string]string{
			"Service.Type": "oneshot", "Service.RemainAfterExit": "yes", "Service.ExecStart": enrolScriptPath, "Unit.ConditionPathExists": "!" + enrolmentJSONPath}},
		{name: "k3s requires and follows enrolment", path: k3sEnrolDropIn, listed: []string{"Unit.Requires=" + enrolUnitName, "Unit.After=" + enrolUnitName}},
		{name: "the metadata guard loads its ruleset before k3s", path: metadataGuardUnitPath, perms: "0644", listed: []string{"Unit.Before=k3s.service", "Install.WantedBy=multi-user.target"},
			one: map[string]string{"Service.Type": "oneshot", "Service.RemainAfterExit": "yes", "Service.ExecStart": metadataGuardNftCommand}},
		{name: "k3s requires and follows the metadata guard", path: k3sMetadataGuardDropIn, perms: "0644", listed: []string{"Unit.Requires=" + metadataGuardUnitName, "Unit.After=" + metadataGuardUnitName}},
		{name: "apt-daily-upgrade installs at 01:30 UTC with no random delay", path: aptDailyUpgradeDropIn, perms: "0644",
			assigned: map[string][]string{"Timer.OnCalendar": {"", "*-*-* 01:30:00 UTC"}}, spans: map[string]time.Duration{"Timer.RandomizedDelaySec": 0}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { assertUnitRow(t, cc, r) })
	}
}

func assertUnitRow(t *testing.T, cc testutil.CloudConfig, r unitRow) {
	t.Helper()
	u := renderedUnit(t, cc, r.path)
	if r.perms != "" {
		testutil.FailIf(t, cc.File(t, r.path).Permissions != r.perms, "%s permissions = %q, want %s", r.path, cc.File(t, r.path).Permissions, r.perms)
	}
	split := func(k string) (string, string) { section, key, _ := strings.Cut(k, "."); return section, key }
	for k, want := range r.one {
		section, key := split(k)
		got := u.one(t, r.path, section, key)
		testutil.FailIf(t, got != want, "%s [%s] %s = %q, want %q", r.path, section, key, got, want)
	}
	for _, l := range r.listed {
		k, name, _ := strings.Cut(l, "=")
		section, key := split(k)
		testutil.FailIf(t, !u.listed(section, key, name), "%s does not list %s in %s: %v", r.path, name, k, u[section])
	}
	for k, want := range r.spans {
		section, key := split(k)
		raw := u.one(t, r.path, section, key)
		got, ok := systemdSpan(raw)
		testutil.FailIf(t, !ok || got != want, "%s %s = %q, want a span of %s", r.path, k, raw, want)
	}
	for k, want := range r.assigned {
		section, key := split(k)
		testutil.FailIf(t, !slices.Equal(u[section][key], want), "%s %s is assigned %q, want %q", r.path, k, u[section][key], want)
	}
	units := u["Timer"]["Unit"]
	testutil.FailIf(t, r.timerOf != "" && len(units) > 0 && !slices.Equal(units, []string{r.timerOf}), "%s Unit = %q, want %s", r.path, units, r.timerOf)
}

func isFullLineComment(line string) bool {
	t := strings.TrimLeft(line, " \t")
	return strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!")
}

func embeddedScriptPaths() []string {
	return []string{nodeScriptPath, enrolScriptPath, installerPath}
}

func isBlankLine(line string) bool { return strings.TrimSpace(line) == "" }

func TestRenderUserData_EmbeddedScriptsCarryNoFullLineCommentOrBlankLineButKeepTheirShebang(t *testing.T) {
	inputs := map[string]UserDataInputs{"the fixture inputs": fixtureRenderInputs(), "the longest inputs": longestRenderInputs()}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			_, cc := renderCC(t, in)

			for _, path := range embeddedScriptPaths() {
				content := cc.File(t, path).Content
				testutil.FailIf(t, !strings.HasPrefix(content, "#!"), "%s starts with %q, want its #! shebang", path, testutil.FirstLine(content))
				body, ended := strings.CutSuffix(content, "\n")
				testutil.FailIf(t, !ended, "%s does not end in a newline, which a here-document on its last line needs", path)
				for i, line := range strings.Split(body, "\n") {
					testutil.FailIf(t, isFullLineComment(line), "%s line %d is a full-line comment: %q", path, i+1, line)
					testutil.FailIf(t, isBlankLine(line), "%s line %d is blank", path, i+1)
				}
			}
		})
	}
}

var hereDocOpener = regexp.MustCompile(`<<-?\s*'?"?([A-Za-z_][A-Za-z0-9_]*)'?"?`)

func TestRenderUserData_NoEmbeddedScriptWritesABlankLineThroughAHereDocument(t *testing.T) {
	installer, err := renderInstaller(fixtureRenderInputs().Versions)
	testutil.FatalIf(t, err != nil, "renderInstaller: %v", err)
	sources := map[string]string{nodeScriptPath: nodeScript, enrolScriptPath: enrolScript, installerPath: installer}
	opened := 0
	for _, path := range embeddedScriptPaths() {
		lines := strings.Split(sources[path], "\n")
		for i := 0; i < len(lines); i++ {
			m := hereDocOpener.FindStringSubmatch(lines[i])
			if m == nil || isFullLineComment(lines[i]) {
				continue
			}
			opened++
			python := m[1] == "PY"
			j := i + 1
			for ; j < len(lines) && strings.TrimLeft(lines[j], "\t") != m[1]; j++ {
				testutil.FailIf(t, !python && isBlankLine(lines[j]), "%s line %d is blank inside the here-document opened at line %d, and the render drops blank lines", path, j+1, i+1)
			}
			i = j
		}
	}
	testutil.FailIf(t, opened == 0, "no embedded script opens a here-document, so the check above pins nothing")
}

func TestRenderUserData_StrippingRemovesOnlyFullLineCommentsAndBlankLinesFromEachScript(t *testing.T) {
	in := fixtureRenderInputs()
	installer, err := renderInstaller(in.Versions)
	testutil.FatalIf(t, err != nil, "renderInstaller: %v", err)
	sources := map[string]string{
		nodeScriptPath:  nodeScript,
		enrolScriptPath: enrolScript,
		installerPath:   installer,
	}
	for _, path := range embeddedScriptPaths() {
		t.Run(path, func(t *testing.T) {
			source := sources[path]
			body, _ := strings.CutSuffix(source, "\n")
			var want []string
			for _, line := range strings.Split(body, "\n") {
				if !isFullLineComment(line) && !isBlankLine(line) {
					want = append(want, line)
				}
			}
			want = append(want, "")
			testutil.FatalIf(t, len(want) == len(strings.Split(source, "\n")), "%s has no full-line comment or blank line in its source, so the check below pins nothing", path)

			f, err := ScriptFile(path, source)
			testutil.FatalIf(t, err != nil, "scriptFile(%s): %v", path, err)
			got := strings.Split(testutil.DecodeContent(t, testutil.CloudFile{Path: f.Path, Content: f.Content, Encoding: f.Encoding}), "\n")

			testutil.FailIf(t, !slices.Equal(got, want), "%s rendered %d lines, want the source's %d lines that are neither comment nor blank in order, byte-identical, then its final newline; first difference: %s",
				path, len(got), len(want), firstLineDifference(got, want))
		})
	}
}

func firstLineDifference(got, want []string) string {
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			return fmt.Sprintf("line %d is %q, want %q", i+1, got[i], want[i])
		}
	}
	return fmt.Sprintf("lengths %d and %d", len(got), len(want))
}
