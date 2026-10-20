package cluster

// bootsecrets_test.go pins how mitstack's own cluster gets the GitHub App's key and initialises OpenBao through Git alone.

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const (
	openBaoBootFile   = bootDir + "/04-openbao-boot.yaml"
	wantBootNamespace = "mitstack-node"
)

func wantNodeAgentImage(t *testing.T) string {
	return "ghcr.io/mitstack-eu/mitstack-node-agent@" + strings.TrimSpace(testRepoFile(t, "scripts/nodeagent/digest"))
}

func TestRenderUserData_HostsPlatformInitialisesOpenBaoAndWritesTheAppKeyAndAppSecretsFromTheNodeAgentsImage(t *testing.T) {
	_, cc := renderCC(t, hostsPlatformRenderInputs())
	docs := bootDocs(t, cc)
	repo := strings.TrimPrefix(fixtureRepoURL, "https://github.com/")

	f := cc.file(t, openBaoBootFile)
	failIf(t, path.Base(f.Path) >= "10-cluster-root.yaml" || f.Permissions != "0600", "%s is %s, want it applied before 10-cluster-root.yaml and root-only", f.Path, f.Permissions)
	_, ns := onlyDoc(t, docs, "Namespace", wantBootNamespace)
	agentNamespace := yamlMap(t, "node-agent.yaml", strings.SplitN(testRepoFile(t, "scripts/nodeagent/node-agent.yaml"), "---\n", 2)[0])
	failIf(t, fmt.Sprint(dig(ns, "metadata", "labels")) != fmt.Sprint(dig(agentNamespace, "metadata", "labels")), "%s carries %v, want the node agent's labels %v, so Argo CD's later sync changes nothing", wantBootNamespace, dig(ns, "metadata", "labels"), dig(agentNamespace, "metadata", "labels"))

	_, job := onlyDoc(t, docs, "Job", "openbao-init")
	_, writer := onlyDoc(t, docs, "Deployment", "github-app-writer")
	_, appSecretsWriter := onlyDoc(t, docs, "Deployment", "app-secrets-writer")
	for _, c := range []struct {
		name        string
		pod         any
		command     []string
		account     string
		mountsToken bool
		secret      string
	}{
		{"the init Job", dig(job, "spec", "template"), []string{"mitstack-openbao", "init"}, "openbao-init", false, "github-app-key"},
		{"the writer", dig(writer, "spec", "template"), []string{"mitstack-openbao", "write-app-key"}, "github-app-writer", true, "github-app-key"},
		{"the app secrets writer", dig(appSecretsWriter, "spec", "template"), []string{"mitstack-openbao", "write-app-secrets"}, "app-secrets-writer", true, "app-secrets"},
	} {
		t.Run(c.name, func(t *testing.T) {
			containers, _ := dig(c.pod, "spec", "containers").([]any)
			fatalIf(t, len(containers) != 1, "%s runs %d containers, want one", c.name, len(containers))
			ctr := containers[0]
			failIf(t, dig(ctr, "image") != wantNodeAgentImage(t), "%s runs %v, want the pinned node agent %s", c.name, dig(ctr, "image"), wantNodeAgentImage(t))
			failIf(t, !slices.Equal(stringsOf(t, "command", dig(ctr, "command")), c.command), "%s runs %v, want %v", c.name, dig(ctr, "command"), c.command)
			failIf(t, dig(ctr, "resources", "limits", "cpu") == nil || dig(ctr, "resources", "limits", "memory") == nil, "%s sets no CPU or memory limit, which the admission policies require in %s", c.name, wantBootNamespace)
			failIf(t, dig(c.pod, "metadata", "labels", "mitstack.dev/app") == nil, "%s carries no mitstack.dev/app label, which the admission policies require", c.name)
			failIf(t, dig(c.pod, "spec", "serviceAccountName") != c.account, "%s runs as %v, want %s", c.name, dig(c.pod, "spec", "serviceAccountName"), c.account)
			_, account := onlyDoc(t, docs, "ServiceAccount", c.account)
			failIf(t, (account["automountServiceAccountToken"] != false) != c.mountsToken, "%s mounts a service account token: %v, want %v", c.name, account["automountServiceAccountToken"] != false, c.mountsToken)
			failIf(t, !strings.Contains(fmt.Sprint(dig(c.pod, "spec", "volumes")), "secretName:"+c.secret), "%s does not mount the Secret %s", c.name, c.secret)
			failIf(t, !mountsOpenBaoCA(c.pod), "%s does not mount the ConfigMap openbao-ca read-only at %s, where mitstack-openbao reads the authority it verifies OpenBao against", c.name, wantOpenBaoCADir)
		})
	}
	volumes, _ := dig(appSecretsWriter, "spec", "template", "spec", "volumes").([]any)
	fatalIf(t, len(volumes) != 2, "the app secrets writer mounts %d volumes, want the Secret app-secrets and OpenBao's authority alone", len(volumes))
	secret := volumes[slices.IndexFunc(volumes, func(v any) bool { return dig(v, "configMap") == nil })]
	failIf(t, dig(secret, "secret", "secretName") != "app-secrets" || dig(secret, "secret", "optional") != true,
		"the app secrets writer mounts %v, want the Secret app-secrets as optional, so it starts before any app's value is sealed", secret)
	appContainers, _ := dig(appSecretsWriter, "spec", "template", "spec", "containers").([]any)
	mounts, _ := dig(appContainers[0], "volumeMounts").([]any)
	at := slices.IndexFunc(mounts, func(m any) bool { return dig(m, "name") == dig(secret, "name") })
	fatalIf(t, at < 0, "the app secrets writer mounts %v, want app-secrets among them", mounts)
	failIf(t, dig(mounts[at], "mountPath") != "/etc/mitstack/app-secrets" || dig(mounts[at], "readOnly") != true,
		"the app secrets writer mounts %v, want app-secrets read-only at /etc/mitstack/app-secrets, where mitstack-openbao write-app-secrets reads", mounts[at])
	containers, _ := dig(job, "spec", "template", "spec", "containers").([]any)
	var env []string
	for _, v := range dig(containers[0], "env").([]any) {
		env = append(env, fmt.Sprintf("%v=%v", dig(v, "name"), dig(v, "value")))
	}
	for _, want := range []string{"MITSTACK_REPOSITORY=" + repo, "MITSTACK_GITHUB_APP_ID=" + fixtureGitHubAppID, "MITSTACK_GITHUB_INSTALLATION_ID=" + fixtureInstallationID} {
		failIf(t, !slices.Contains(env, want), "the init Job runs with %v, want %s", env, want)
	}
	_, recipient := onlyDoc(t, docs, "ConfigMap", "openbao-recipient")
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(fmt.Sprint(dig(recipient, "data", "recipient.asc"))))
	want, _ := openpgp.ReadArmoredKeyRing(strings.NewReader(bootFixture("owner.asc")))
	fatalIf(t, err != nil || len(keys) != 1, "the recipient the Job encrypts to is not one OpenPGP key: %v", err)
	failIf(t, keys[0].PrimaryKey.KeyIdString() != want[0].PrimaryKey.KeyIdString(), "the Job encrypts to key %s, want the owner's %s", keys[0].PrimaryKey.KeyIdString(), want[0].PrimaryKey.KeyIdString())
}

func TestReadSealedAppKey_KeepsOnlyTheSealedKey(t *testing.T) {
	app, err := ReadSealedAppKey(bootFixture("github-app-key.sealed.yaml"))
	fatalIf(t, err != nil, "readSealedAppKey: %v", err)

	got, err := marshalYAML(app)

	fatalIf(t, err != nil, "marshalling: %v", err)
	doc := yamlMap(t, "the re-rendered sealed key", got)
	failIf(t, len(doc) != 4 || len(dig(doc, "metadata").(map[string]any)) != 2, "the re-rendered sealed key holds %v, want only apiVersion, kind, name, namespace and spec", doc)
	failIf(t, dig(doc, "spec", "template", "metadata", "name") != "github-app-key", "the opened Secret is named %v, want github-app-key", dig(doc, "spec", "template", "metadata", "name"))
}

func TestSealedAppKey_OpensOnlyWithTheKeyKubesealSealedItAgainst(t *testing.T) {
	app, err := ReadSealedAppKey(bootFixture("github-app-key.sealed.yaml"))
	fatalIf(t, err != nil, "readSealedAppKey: %v", err)
	keyPEM, certPEM, err := MintSealedSecretsKeyPair()
	fatalIf(t, err != nil, "minting a pair: %v", err)

	sealedFor := SealedSecretsInputs{KeyPEM: bootFixture("sealed-secrets.key"), CertPEM: bootFixture("sealed-secrets.crt")}.Opens(app)
	other := SealedSecretsInputs{KeyPEM: keyPEM, CertPEM: certPEM}.Opens(app)

	failIf(t, sealedFor != nil, "kubeseal's file does not open with the key it was sealed against: %v", sealedFor)
	failIf(t, other == nil, "kubeseal's file opens with a key it was not sealed against")
}
