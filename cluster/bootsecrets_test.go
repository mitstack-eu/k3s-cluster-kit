package cluster

// bootsecrets_test.go pins how mitstack's own cluster gets the GitHub App's key and initialises OpenBao through Git alone.

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	openBaoBootFile   = testutil.BootDir + "/04-openbao-boot.yaml"
	wantBootNamespace = "mitstack-node"
)

func wantNodeAgentImage(t *testing.T) string {
	return "ghcr.io/mitstack-eu/mitstack-node-agent@" + strings.TrimSpace(testutil.TestRepoFile(t, "scripts/nodeagent/digest"))
}

func TestRenderUserData_HostsPlatformInitialisesOpenBaoAndWritesTheAppKeyAndAppSecretsFromTheNodeAgentsImage(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := testutil.BootDocs(t, cc)
	repo := strings.TrimPrefix(testutil.FixtureRepoURL, "https://github.com/")

	f := cc.File(t, openBaoBootFile)
	testutil.FailIf(t, path.Base(f.Path) >= "10-cluster-root.yaml" || f.Permissions != "0600", "%s is %s, want it applied before 10-cluster-root.yaml and root-only", f.Path, f.Permissions)
	_, ns := testutil.OnlyDoc(t, docs, "Namespace", wantBootNamespace)
	agentNamespace := testutil.YamlMap(t, "node-agent.yaml", strings.SplitN(testutil.TestRepoFile(t, "scripts/nodeagent/node-agent.yaml"), "---\n", 2)[0])
	testutil.FailIf(t, fmt.Sprint(testutil.Dig(ns, "metadata", "labels")) != fmt.Sprint(testutil.Dig(agentNamespace, "metadata", "labels")), "%s carries %v, want the node agent's labels %v, so Argo CD's later sync changes nothing", wantBootNamespace, testutil.Dig(ns, "metadata", "labels"), testutil.Dig(agentNamespace, "metadata", "labels"))

	_, job := testutil.OnlyDoc(t, docs, "Job", "openbao-init")
	_, writer := testutil.OnlyDoc(t, docs, "Deployment", "github-app-writer")
	_, appSecretsWriter := testutil.OnlyDoc(t, docs, "Deployment", "app-secrets-writer")
	for _, c := range []struct {
		name        string
		pod         any
		command     []string
		account     string
		mountsToken bool
		secret      string
	}{
		{"the init Job", testutil.Dig(job, "spec", "template"), []string{"mitstack-openbao", "init"}, "openbao-init", false, "github-app-key"},
		{"the writer", testutil.Dig(writer, "spec", "template"), []string{"mitstack-openbao", "write-app-key"}, "github-app-writer", true, "github-app-key"},
		{"the app secrets writer", testutil.Dig(appSecretsWriter, "spec", "template"), []string{"mitstack-openbao", "write-app-secrets"}, "app-secrets-writer", true, "app-secrets"},
	} {
		t.Run(c.name, func(t *testing.T) {
			containers, _ := testutil.Dig(c.pod, "spec", "containers").([]any)
			testutil.FatalIf(t, len(containers) != 1, "%s runs %d containers, want one", c.name, len(containers))
			ctr := containers[0]
			testutil.FailIf(t, testutil.Dig(ctr, "image") != wantNodeAgentImage(t), "%s runs %v, want the pinned node agent %s", c.name, testutil.Dig(ctr, "image"), wantNodeAgentImage(t))
			testutil.FailIf(t, !slices.Equal(stringsOf(t, "command", testutil.Dig(ctr, "command")), c.command), "%s runs %v, want %v", c.name, testutil.Dig(ctr, "command"), c.command)
			testutil.FailIf(t, testutil.Dig(ctr, "resources", "limits", "cpu") == nil || testutil.Dig(ctr, "resources", "limits", "memory") == nil, "%s sets no CPU or memory limit, which the admission policies require in %s", c.name, wantBootNamespace)
			testutil.FailIf(t, testutil.Dig(c.pod, "metadata", "labels", "mitstack.dev/app") == nil, "%s carries no mitstack.dev/app label, which the admission policies require", c.name)
			testutil.FailIf(t, testutil.Dig(c.pod, "spec", "serviceAccountName") != c.account, "%s runs as %v, want %s", c.name, testutil.Dig(c.pod, "spec", "serviceAccountName"), c.account)
			_, account := testutil.OnlyDoc(t, docs, "ServiceAccount", c.account)
			testutil.FailIf(t, (account["automountServiceAccountToken"] != false) != c.mountsToken, "%s mounts a service account token: %v, want %v", c.name, account["automountServiceAccountToken"] != false, c.mountsToken)
			testutil.FailIf(t, !strings.Contains(fmt.Sprint(testutil.Dig(c.pod, "spec", "volumes")), "secretName:"+c.secret), "%s does not mount the Secret %s", c.name, c.secret)
			testutil.FailIf(t, !mountsOpenBaoCA(c.pod), "%s does not mount the ConfigMap openbao-ca read-only at %s, where mitstack-openbao reads the authority it verifies OpenBao against", c.name, wantOpenBaoCADir)
		})
	}
	volumes, _ := testutil.Dig(appSecretsWriter, "spec", "template", "spec", "volumes").([]any)
	testutil.FatalIf(t, len(volumes) != 2, "the app secrets writer mounts %d volumes, want the Secret app-secrets and OpenBao's authority alone", len(volumes))
	secret := volumes[slices.IndexFunc(volumes, func(v any) bool { return testutil.Dig(v, "configMap") == nil })]
	testutil.FailIf(t, testutil.Dig(secret, "secret", "secretName") != "app-secrets" || testutil.Dig(secret, "secret", "optional") != true,
		"the app secrets writer mounts %v, want the Secret app-secrets as optional, so it starts before any app's value is sealed", secret)
	appContainers, _ := testutil.Dig(appSecretsWriter, "spec", "template", "spec", "containers").([]any)
	mounts, _ := testutil.Dig(appContainers[0], "volumeMounts").([]any)
	at := slices.IndexFunc(mounts, func(m any) bool { return testutil.Dig(m, "name") == testutil.Dig(secret, "name") })
	testutil.FatalIf(t, at < 0, "the app secrets writer mounts %v, want app-secrets among them", mounts)
	testutil.FailIf(t, testutil.Dig(mounts[at], "mountPath") != "/etc/mitstack/app-secrets" || testutil.Dig(mounts[at], "readOnly") != true,
		"the app secrets writer mounts %v, want app-secrets read-only at /etc/mitstack/app-secrets, where mitstack-openbao write-app-secrets reads", mounts[at])
	containers, _ := testutil.Dig(job, "spec", "template", "spec", "containers").([]any)
	var env []string
	for _, v := range testutil.Dig(containers[0], "env").([]any) {
		env = append(env, fmt.Sprintf("%v=%v", testutil.Dig(v, "name"), testutil.Dig(v, "value")))
	}
	for _, want := range []string{"MITSTACK_REPOSITORY=" + repo, "MITSTACK_GITHUB_APP_ID=" + testutil.FixtureGitHubAppID, "MITSTACK_GITHUB_INSTALLATION_ID=" + testutil.FixtureInstallationID} {
		testutil.FailIf(t, !slices.Contains(env, want), "the init Job runs with %v, want %s", env, want)
	}
	_, recipient := testutil.OnlyDoc(t, docs, "ConfigMap", "openbao-recipient")
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(fmt.Sprint(testutil.Dig(recipient, "data", "recipient.asc"))))
	want, _ := openpgp.ReadArmoredKeyRing(strings.NewReader(bootFixture("owner.asc")))
	testutil.FatalIf(t, err != nil || len(keys) != 1, "the recipient the Job encrypts to is not one OpenPGP key: %v", err)
	testutil.FailIf(t, keys[0].PrimaryKey.KeyIdString() != want[0].PrimaryKey.KeyIdString(), "the Job encrypts to key %s, want the owner's %s", keys[0].PrimaryKey.KeyIdString(), want[0].PrimaryKey.KeyIdString())
}

func TestReadSealedAppKey_KeepsOnlyTheSealedKey(t *testing.T) {
	app, err := ReadSealedAppKey(bootFixture("github-app-key.sealed.yaml"))
	testutil.FatalIf(t, err != nil, "readSealedAppKey: %v", err)

	got, err := marshalYAML(app)

	testutil.FatalIf(t, err != nil, "marshalling: %v", err)
	doc := testutil.YamlMap(t, "the re-rendered sealed key", got)
	testutil.FailIf(t, len(doc) != 4 || len(testutil.Dig(doc, "metadata").(map[string]any)) != 2, "the re-rendered sealed key holds %v, want only apiVersion, kind, name, namespace and spec", doc)
	testutil.FailIf(t, testutil.Dig(doc, "spec", "template", "metadata", "name") != "github-app-key", "the opened Secret is named %v, want github-app-key", testutil.Dig(doc, "spec", "template", "metadata", "name"))
}

func TestSealedAppKey_OpensOnlyWithTheKeyKubesealSealedItAgainst(t *testing.T) {
	app, err := ReadSealedAppKey(bootFixture("github-app-key.sealed.yaml"))
	testutil.FatalIf(t, err != nil, "readSealedAppKey: %v", err)
	keyPEM, certPEM, err := MintSealedSecretsKeyPair()
	testutil.FatalIf(t, err != nil, "minting a pair: %v", err)

	sealedFor := SealedSecretsInputs{KeyPEM: bootFixture("sealed-secrets.key"), CertPEM: bootFixture("sealed-secrets.crt")}.Opens(app)
	other := SealedSecretsInputs{KeyPEM: keyPEM, CertPEM: certPEM}.Opens(app)

	testutil.FailIf(t, sealedFor != nil, "kubeseal's file does not open with the key it was sealed against: %v", sealedFor)
	testutil.FailIf(t, other == nil, "kubeseal's file opens with a key it was not sealed against")
}
