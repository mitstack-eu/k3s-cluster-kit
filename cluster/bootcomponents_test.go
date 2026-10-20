package cluster

// bootcomponents_test.go pins how mitstack's own cluster, whose subscription sets hostsPlatform, boots with no platform running.

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	fixtureSealKey        = "8d26485ad7c5645f1cf12799be1b701d3cccc5cfe56fe967dbf282199e1af1ce"
	fixtureGitHubAppID    = "1234567"
	fixtureInstallationID = "171311443"

	bootDir            = "/var/lib/rancher/k3s/server/manifests"
	sealKeyFile        = bootDir + "/01-openbao-seal-key.yaml"
	credentialFile     = bootDir + "/03-cluster-repository.yaml"
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

var hexSealKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
	in.HostsPlatform = &HostsPlatformInputs{SealKey: fixtureSealKey, AppID: fixtureGitHubAppID, InstallationID: fixtureInstallationID, PublicIPv4: fixtureIngressIPv4,
		Recipient: bootFixture("owner.asc"), SealedSecrets: SealedSecretsInputs{KeyPEM: bootFixture("sealed-secrets.key"), CertPEM: bootFixture("sealed-secrets.crt"), SealedAppKey: app}}
	return in
}

// ownerKey is a fresh OpenPGP key pair and its armored public half, standing in for the owner's.
func ownerKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Owner", "", "owner@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	fatalIf(t, err != nil, "generating the owner's key: %v", err)
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	fatalIf(t, err != nil, "armoring the owner's key: %v", err)
	fatalIf(t, e.Serialize(w) != nil || w.Close() != nil, "serializing the owner's key")
	return e, b.String()
}

func decryptFor(t *testing.T, e *openpgp.Entity, message string) string {
	t.Helper()
	block, err := armor.Decode(strings.NewReader(message))
	fatalIf(t, err != nil || block.Type != "PGP MESSAGE", "%q is not an armored PGP message: %v", message, err)
	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{e}, nil, nil)
	fatalIf(t, err != nil, "the owner's key cannot decrypt the message: %v", err)
	plain, err := io.ReadAll(md.UnverifiedBody)
	fatalIf(t, err != nil, "reading the decrypted message: %v", err)
	return string(plain)
}

// bootDocs maps each file in k3s's auto-deploy directory to the documents it holds.
func bootDocs(t *testing.T, cc cloudConfig) map[string][]map[string]any {
	t.Helper()
	docs := map[string][]map[string]any{}
	for _, f := range cc.WriteFiles {
		if path.Dir(f.Path) == bootDir && strings.HasSuffix(f.Path, ".yaml") {
			docs[path.Base(f.Path)] = yamlDocs(t, f.Path, f.Content)
		}
	}
	return docs
}

// onlyDoc finds the one document of a kind and name, and the file that holds it.
func onlyDoc(t *testing.T, docs map[string][]map[string]any, kind, name string) (string, map[string]any) {
	t.Helper()
	var file string
	var found []map[string]any
	for f, list := range docs {
		for _, d := range list {
			if d["kind"] == kind && dig(d, "metadata", "name") == name {
				file, found = f, append(found, d)
			}
		}
	}
	fatalIf(t, len(found) != 1, "the auto-deploy directory holds %d %s %s, want exactly one", len(found), kind, name)
	return file, found[0]
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
	text, ok := dig(chart, "spec", "valuesContent").(string)
	fatalIf(t, !ok, "%s carries no valuesContent", what)
	return yamlMap(t, what+" values", text)
}

// sealKeyOf reads the seal key a node's user data writes.
func sealKeyOf(t *testing.T, cc cloudConfig) string {
	t.Helper()
	f := cc.file(t, sealKeyFile)
	_, secret := onlyDoc(t, map[string][]map[string]any{path.Base(f.Path): yamlDocs(t, f.Path, f.Content)}, "Secret", "openbao-seal-key")
	key, _ := dig(secret, "stringData", "key").(string)
	fatalIf(t, !hexSealKey.MatchString(key), "the seal key is %d characters, want 64 hex", len(key))
	return key
}

func TestClusterBases_TheBlockCarriesEachBootComponentAsTheReleaseHoldsIt(t *testing.T) {
	for component, want := range wantBootTrees {
		t.Run(component, func(t *testing.T) {
			entries, err := os.ReadDir("clusterbases/" + component)
			fatalIf(t, err != nil, "reading clusterbases/%s: %v", component, err)
			files := map[string]string{}
			for _, e := range entries {
				files[e.Name()] = testRepoFile(t, "clusterbases/"+component+"/"+e.Name())
			}

			got := gitTreeID(files)

			failIf(t, got != want, "clusterbases/%s is git tree %s holding %v, want %s, its tree at cluster-bases %s", component, got, slices.Sorted(maps.Keys(files)), want, wantClusterBasesTag)
		})
	}
}

func TestRenderUserData_HostsPlatformStartsK3sWithoutWaitingForEnrolment(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())

	got := strings.Split(runcmdChain(t, cc), " && ")

	want := []string{sshMask, "systemctl daemon-reload", metadataGuardStart, "install -d -m 0700 " + wantOpenBaoDataDir, cc.nodeScript(t).Path,
		autoUpgradeEnable, aptDailyRefreshNow, cc.installer(t).Path, "systemctl enable --now k3s", "systemctl enable --now mitstack-enrol.timer"}
	failIf(t, !slices.Equal(got, want), "runcmd = %q\nwant %q", got, want)
	for _, f := range cc.WriteFiles {
		failIf(t, f.Path == k3sEnrolDropIn, "the user data writes %s, so k3s would wait for enrolment", k3sEnrolDropIn)
	}
	failIf(t, cc.enrolScript(t).Path != enrolScriptPath, "the enrol script is at %s, want %s", cc.enrolScript(t).Path, enrolScriptPath)
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
	docs := bootDocs(t, cc)

	for _, component := range slices.Sorted(maps.Keys(wantBootTrees)) {
		t.Run(component, func(t *testing.T) {
			file, chart := onlyDoc(t, docs, "HelmChart", component)
			base := yamlMap(t, component, testRepoFile(t, "clusterbases/"+component+"/helmchart.yaml"))
			values, baseValues := chartValuesOf(t, component, chart), chartValuesOf(t, "cluster-bases "+component, base)

			failIf(t, file >= "10-cluster-root.yaml", "%s boots from %s, which k3s applies after 10-cluster-root.yaml", component, file)
			for _, field := range []string{"chart", "repo", "version", "targetNamespace"} {
				failIf(t, dig(chart, "spec", field) != dig(base, "spec", field), "%s spec.%s = %v, want %v", component, field, dig(chart, "spec", field), dig(base, "spec", field))
			}
			for k, want := range baseValues {
				failIf(t, !reflect.DeepEqual(values[k], want), "%s values.%s = %v, want %v as cluster-bases %s sets it", component, k, values[k], want, wantClusterBasesTag)
			}
			tags := imageTags(values)
			failIf(t, len(tags) == 0, "%s's values set no image tag", component)
			for _, tag := range tags {
				failIf(t, !imageByDigest.MatchString(tag), "%s names an image by %q, want a digest", component, tag)
			}
		})
	}
	_, traefik := onlyDoc(t, docs, "HelmChart", "traefik")
	assertPaths(t, "the booted Traefik", chartValuesOf(t, "traefik", traefik), map[string]any{
		"providers.kubernetesIngress.ingressEndpoint.ip": fixtureIngressIPv4,
		"ports.websecure.nodePort":                       HTTPSNodePort,
	})
	_, pv := onlyDoc(t, docs, "PersistentVolume", "openbao-data")
	failIf(t, dig(pv, "spec", "local", "path") != wantOpenBaoDataDir, "OpenBao's volume is at %v, want %s", dig(pv, "spec", "local", "path"), wantOpenBaoDataDir)
}

func TestRenderUserData_HostsPlatformTakesArgoCDsRepositoryCredentialFromAGitHubApp(t *testing.T) {
	ud, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := bootDocs(t, cc)

	for _, absent := range []string{"mitstack-repo-token", "cluster-repository-tokens"} {
		failIf(t, strings.Contains(cc.allText(ud), absent), "the user data names %s; want no token refresh against the platform", absent)
	}
	skip := cc.file(t, bootDir+"/05-cluster-repository.yaml.skip")
	failIf(t, skip.Owner != "root:root" || skip.Permissions != "0600", "%s is %s %s, want root:root 0600", skip.Path, skip.Owner, skip.Permissions)

	file, secret := onlyDoc(t, docs, "ExternalSecret", "cluster-repository")
	failIf(t, path.Join(bootDir, file) != credentialFile, "the repository credential boots from %s, want %s", file, credentialFile)
	assertPaths(t, "ExternalSecret cluster-repository", secret, map[string]any{
		"metadata.namespace":                 "argocd",
		"spec.target.name":                   "cluster-repository",
		"spec.target.template.data.url":      fixtureRepoURL,
		"spec.target.template.data.username": "x-access-token",
		"spec.target.template.data.password": "{{ .token }}",
	})
	failIf(t, dig(secret, "spec", "target", "template", "metadata", "labels", "argocd.argoproj.io/secret-type") != "repository", "the Secret carries no Argo CD repository label")
	from, _ := dig(secret, "spec", "dataFrom").([]any)
	fatalIf(t, len(from) != 1, "spec.dataFrom has %d entries, want the GitHub generator alone", len(from))
	failIf(t, dig(from[0], "sourceRef", "generatorRef", "kind") != "GithubAccessToken", "the token comes from %v, want External Secrets' GitHub generator", dig(from[0], "sourceRef", "generatorRef", "kind"))

	_, generator := onlyDoc(t, docs, "GithubAccessToken", fmt.Sprint(dig(from[0], "sourceRef", "generatorRef", "name")))
	assertPaths(t, "the GitHub generator", generator, map[string]any{
		"metadata.namespace":                 "argocd",
		"spec.appID":                         fixtureGitHubAppID,
		"spec.installID":                     fixtureInstallationID,
		"spec.auth.privateKey.secretRef.key": "private-key",
	})
	failIf(t, !slices.Equal(stringsOf(t, "spec.repositories", dig(generator, "spec", "repositories")), []string{fixtureRepoName}), "the token reads %v, want only %s", dig(generator, "spec", "repositories"), fixtureRepoName)

	_, key := onlyDoc(t, docs, "ExternalSecret", fmt.Sprint(dig(generator, "spec", "auth", "privateKey", "secretRef", "name")))
	data, _ := dig(key, "spec", "data").([]any)
	fatalIf(t, len(data) != 1, "the App key's ExternalSecret copies %d values, want one", len(data))
	assertPaths(t, "the App key's source", data[0].(map[string]any), map[string]any{"secretKey": "private-key", "remoteRef.key": "argocd/github-app", "remoteRef.property": "private-key"})
	_, store := onlyDoc(t, docs, "SecretStore", fmt.Sprint(dig(key, "spec", "secretStoreRef", "name")))
	assertPaths(t, "the OpenBao store", store, map[string]any{
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
	docs := bootDocs(t, cc)

	_, chart := onlyDoc(t, docs, "HelmChart", "openbao")
	values := chartValuesOf(t, "openbao", chart)
	config := fmt.Sprint(dig(values, "server", "standalone", "config"))
	file, serving := onlyDoc(t, docs, "Certificate", "openbao-tls")
	_, authority := onlyDoc(t, docs, "Certificate", "openbao-ca")
	_, issuer := onlyDoc(t, docs, "Issuer", "openbao-ca")
	_, bundle := onlyDoc(t, docs, "Bundle", "openbao-ca")

	block := listenerBlockRe.FindStringSubmatch(config)
	fatalIf(t, block == nil, "OpenBao's configuration holds no tcp listener:\n%s", config)
	listener := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(block[1]), "\n") {
		key, value, _ := strings.Cut(line, "=")
		listener[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	failIf(t, !reflect.DeepEqual(listener, map[string]string{"address": "[::]:8200", "cluster_address": "[::]:8201",
		"tls_cert_file": "/openbao/tls/tls.crt", "tls_key_file": "/openbao/tls/tls.key", "tls_min_version": "tls13"}),
		"OpenBao's tcp listener sets %v, want TLS 1.3 alone on 8200 from the certificate and key in /openbao/tls", listener)
	failIf(t, !strings.Contains(fmt.Sprint(dig(values, "server", "volumes")), "secretName:openbao-tls"), "OpenBao mounts %v, want the Secret openbao-tls the certificate is kept in", dig(values, "server", "volumes"))
	failIf(t, file >= "03-cluster-repository.yaml", "the certificate boots from %s, after the store that reads OpenBao over TLS", file)
	assertPaths(t, "the serving certificate", serving, map[string]any{
		"metadata.namespace":  "openbao",
		"spec.secretName":     "openbao-tls",
		"spec.issuerRef.kind": "Issuer",
		"spec.issuerRef.name": dig(issuer, "metadata", "name"),
	})
	failIf(t, !slices.Contains(stringsOf(t, "spec.dnsNames", dig(serving, "spec", "dnsNames")), "openbao.openbao.svc"), "the certificate names %v, want openbao.openbao.svc", dig(serving, "spec", "dnsNames"))
	lifetime, err := time.ParseDuration(fmt.Sprint(dig(serving, "spec", "duration")))
	fatalIf(t, err != nil, "the certificate's duration: %v", err)
	before, err := time.ParseDuration(fmt.Sprint(dig(serving, "spec", "renewBefore")))
	failIf(t, err != nil || before <= 0 || before >= lifetime, "the certificate renews %v before its %v lifetime ends, want a renewal inside it", dig(serving, "spec", "renewBefore"), lifetime)
	assertPaths(t, "the authority", authority, map[string]any{
		"metadata.namespace":             "openbao",
		"spec.isCA":                      true,
		"spec.privateKey.rotationPolicy": "Never",
		"spec.secretName":                dig(issuer, "spec", "ca", "secretName"),
		"spec.issuerRef.kind":            "Issuer",
	})
	failIf(t, dig(issuer, "metadata", "namespace") != "openbao", "the authority signs from namespace %v, want openbao alone", dig(issuer, "metadata", "namespace"))
	sources, _ := dig(bundle, "spec", "sources").([]any)
	fatalIf(t, len(sources) != 1, "the Bundle copies %d sources, want the authority alone", len(sources))
	failIf(t, dig(sources[0], "secret", "name") != dig(authority, "spec", "secretName") || dig(bundle, "spec", "target", "configMap", "key") != "ca.crt",
		"the Bundle copies %v into %v, want the authority's Secret into the ConfigMap key ca.crt", sources[0], dig(bundle, "spec", "target"))
	reload, _ := dig(values, "server", "extraContainers").([]any)
	failIf(t, dig(values, "server", "shareProcessNamespace") != true || len(reload) != 1 || !strings.Contains(fmt.Sprint(dig(reload[0], "volumeMounts")), "mountPath:/openbao/tls"),
		"OpenBao's pod runs %v with shareProcessNamespace %v, want one container that reads the renewed certificate and signals OpenBao", reload, dig(values, "server", "shareProcessNamespace"))
}

func TestRenderUserData_HostsPlatformBootsTheCertManagerEveryClusterRuns(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())

	_, chart := onlyDoc(t, bootDocs(t, cc), "HelmChart", "cert-manager")

	version := PinnedVersions.CertManagerChartVersion
	failIf(t, dig(chart, "spec", "version") != version, "the booted cert-manager is %v, want %s, the version every cluster runs", dig(chart, "spec", "version"), version)
	failIf(t, dig(chartValuesOf(t, "cert-manager", chart), "acmesolver", "image", "digest") != acmesolverDigests[version],
		"the booted cert-manager runs the HTTP-01 solver by %v, want %s, the one digest the admission policy admits", dig(chartValuesOf(t, "cert-manager", chart), "acmesolver", "image", "digest"), acmesolverDigests[version])
}

// mountsOpenBaoCA reports whether pod's one container reads the ConfigMap openbao-ca read-only at wantOpenBaoCADir.
func mountsOpenBaoCA(pod any) bool {
	volumes, _ := dig(pod, "spec", "volumes").([]any)
	containers, _ := dig(pod, "spec", "containers").([]any)
	if len(containers) != 1 {
		return false
	}
	mounts, _ := dig(containers[0], "volumeMounts").([]any)
	for _, v := range volumes {
		for _, m := range mounts {
			if dig(v, "configMap", "name") == "openbao-ca" && dig(m, "name") == dig(v, "name") && dig(m, "mountPath") == wantOpenBaoCADir && dig(m, "readOnly") == true {
				return true
			}
		}
	}
	return false
}

func TestRenderUserData_HostsPlatformWritesTheSealKeyToOneRootOnlyFile(t *testing.T) {
	ud, cc := renderCC(t, hostsPlatformRenderInputs())

	f := cc.file(t, sealKeyFile)

	failIf(t, f.Owner != "root:root" || f.Permissions != "0600", "%s is %s %s, want root:root 0600", f.Path, f.Owner, f.Permissions)
	failIf(t, sealKeyOf(t, cc) != fixtureSealKey, "%s holds another key than the one rendered", f.Path)
	failIf(t, strings.Count(ud, fixtureSealKey) != 1, "the seal key appears %d times in the user data, want only in %s", strings.Count(ud, fixtureSealKey), sealKeyFile)
}

func TestRenderUserData_HostsPlatformRefusesAnInputOutOfShape(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*HostsPlatformInputs)
	}{
		{"a seal key that is not 64 hex characters", func(h *HostsPlatformInputs) { h.SealKey = fixtureSealKey[:63] }},
		{"an App id that is not digits", func(h *HostsPlatformInputs) { h.AppID = "12a" }},
		{"an empty installation id", func(h *HostsPlatformInputs) { h.InstallationID = "" }},
		{"a public address that is not dotted IPv4", func(h *HostsPlatformInputs) { h.PublicIPv4 = "203.0.113.010" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := hostsPlatformRenderInputs()
			c.mutate(in.HostsPlatform)

			_, err := RenderUserData(in)

			failIf(t, err == nil, "RenderUserData accepted %s", c.name)
		})
	}
}
