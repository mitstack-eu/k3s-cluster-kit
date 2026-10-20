package cluster

// The seeded node agent runs the pinned signed image under the rights ADR 0087 grants, judged by Kubernetes' own rule comparator.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/component-helpers/auth/rbac/validation"
)

func nodeAgentDocs(t *testing.T) []map[string]any {
	t.Helper()
	return testutil.YamlDocs(t, seedNodeAgentFile, renderGoldenSeed(t)[seedNodeAgentFile])
}

func decodeDoc(t *testing.T, doc map[string]any, into any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	testutil.FatalIf(t, err != nil || json.Unmarshal(raw, into) != nil, "decoding a %v from the seed: %v", doc["kind"], err)
}

// grantedRules is every rule the seed's bindings give the service account sa in mitstack-node, cluster-wide when
// namespace is empty and in namespace otherwise.
func grantedRules(t *testing.T, docs []map[string]any, sa, namespace string) []rbacv1.PolicyRule {
	t.Helper()
	roles := map[string][]rbacv1.PolicyRule{}
	for _, doc := range docs {
		switch doc["kind"] {
		case "ClusterRole":
			var r rbacv1.ClusterRole
			decodeDoc(t, doc, &r)
			roles["ClusterRole/"+r.Name] = r.Rules
		case "Role":
			var r rbacv1.Role
			decodeDoc(t, doc, &r)
			roles["Role/"+r.Namespace+"/"+r.Name] = r.Rules
		}
	}
	bound := func(subjects []rbacv1.Subject) bool {
		for _, s := range subjects {
			if s.Kind == "ServiceAccount" && s.Name == sa && s.Namespace == "mitstack-node" {
				return true
			}
		}
		return false
	}
	var rules []rbacv1.PolicyRule
	for _, doc := range docs {
		switch doc["kind"] {
		case "ClusterRoleBinding":
			var b rbacv1.ClusterRoleBinding
			decodeDoc(t, doc, &b)
			if bound(b.Subjects) {
				rules = append(rules, roles["ClusterRole/"+b.RoleRef.Name]...)
			}
		case "RoleBinding":
			var b rbacv1.RoleBinding
			decodeDoc(t, doc, &b)
			if b.Namespace == namespace && bound(b.Subjects) {
				key := "Role/" + b.Namespace + "/" + b.RoleRef.Name
				if b.RoleRef.Kind == "ClusterRole" {
					key = "ClusterRole/" + b.RoleRef.Name
				}
				rules = append(rules, roles[key]...)
			}
		}
	}
	return rules
}

func covers(t *testing.T, docs []map[string]any, sa, namespace string, rule rbacv1.PolicyRule) bool {
	t.Helper()
	rules := grantedRules(t, docs, sa, "")
	if namespace != "" {
		rules = append(rules, grantedRules(t, docs, sa, namespace)...)
	}
	ok, _ := validation.Covers(rules, []rbacv1.PolicyRule{rule})
	return ok
}

func secretsRule(verb string, names ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{Verbs: []string{verb}, APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: names}
}

func TestNodeAgentSeed_NoServiceAccountMayListSecretsAnywhereOrGetThemInAnyNamespace(t *testing.T) {
	docs := nodeAgentDocs(t)
	namespaces := []string{"argocd", "kube-system", "system-upgrade", "mitstack-node", "mitstack-metadata-probe", "mitstack-admission-probe",
		"kyverno", "cert-manager", "traefik", "default", "app-shop"}

	for _, sa := range []string{"mitstack-node-report", "mitstack-repo-token"} {
		testutil.FailIf(t, covers(t, docs, sa, "", secretsRule("list")), "%s may list Secrets across all namespaces", sa)
		for _, ns := range namespaces {
			testutil.FailIf(t, covers(t, docs, sa, ns, secretsRule("get")), "%s may get Secrets in %s, which ADR 0087 grants no service account", sa, ns)
		}
	}
}

func TestNodeAgentSeed_GrantsTheReadsTheReportMakesAndOnlyTheRefreshsNamedPatch(t *testing.T) {
	docs := nodeAgentDocs(t)
	rule := func(verb, group, resource string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{Verbs: []string{verb}, APIGroups: []string{group}, Resources: []string{resource}}
	}

	for _, c := range []struct {
		sa, namespace string
		rule          rbacv1.PolicyRule
		want          bool
	}{
		{"mitstack-node-report", "", rule("list", "", "nodes"), true},
		{"mitstack-node-report", "", rule("create", "authorization.k8s.io", "subjectaccessreviews"), true},
		{"mitstack-node-report", "argocd", rule("list", "argoproj.io", "appprojects"), true},
		{"mitstack-node-report", "kube-system", rule("list", "batch", "jobs"), true},
		{"mitstack-node-report", "system-upgrade", rule("list", "upgrade.cattle.io", "plans"), true},
		{"mitstack-node-report", "mitstack-metadata-probe", rule("get", "", "pods/log"), true},
		{"mitstack-node-report", "kube-system", rule("get", "", "pods/log"), false},
		{"mitstack-node-report", "argocd", rule("create", "", "pods/exec"), false},
		{"mitstack-repo-token", "argocd", secretsRule("patch", "cluster-repository"), true},
		{"mitstack-repo-token", "argocd", secretsRule("patch", "argocd-secret"), false},
		{"mitstack-repo-token", "argocd", secretsRule("create"), false},
		{"mitstack-repo-token", "argocd", secretsRule("delete", "cluster-repository"), false},
	} {
		got := covers(t, docs, c.sa, c.namespace, c.rule)
		testutil.FailIf(t, got != c.want, "%s covered for %v in %q = %v, want %v", c.sa, c.rule, c.namespace, got, c.want)
	}
}

func TestNodeAgentSeed_RunsThePinnedImageWithAnAPITokenOnlyInTheReportContainer(t *testing.T) {
	testutil.FailIf(t, !regexp.MustCompile(`^ghcr\.io/mitstack-eu/mitstack-node-agent@sha256:[0-9a-f]{64}$`).MatchString(nodeAgentImage), "the node agent image is %q, want the package named by a digest", nodeAgentImage)
	var agent, refresh map[string]any
	for _, doc := range nodeAgentDocs(t) {
		switch doc["kind"] {
		case "Deployment":
			agent = testutil.Dig(doc, "spec", "template", "spec").(map[string]any)
		case "CronJob":
			refresh = testutil.Dig(doc, "spec", "jobTemplate", "spec", "template", "spec").(map[string]any)
		}
	}
	testutil.FatalIf(t, agent == nil || refresh == nil, "the seed holds no node-agent Deployment or refresh CronJob")

	testutil.FailIf(t, agent["serviceAccountName"] != "mitstack-node-report" || agent["automountServiceAccountToken"] != false || agent["hostPID"] != true,
		"the node-agent pod runs as %v with token automount %v and hostPID %v, want mitstack-node-report, false and true", agent["serviceAccountName"], agent["automountServiceAccountToken"], agent["hostPID"])
	testutil.FailIf(t, refresh["serviceAccountName"] != "mitstack-repo-token", "the refresh runs as %v, want mitstack-repo-token", refresh["serviceAccountName"])
	mounts := map[string][]string{}
	for _, pod := range []map[string]any{agent, refresh} {
		for _, v := range pod["volumes"].([]any) {
			testutil.FailIf(t, v.(map[string]any)["hostPath"] != nil, "a node agent pod mounts a host path: %v", v)
		}
		for _, c := range pod["containers"].([]any) {
			container := c.(map[string]any)
			testutil.FailIf(t, container["image"] != nodeAgentImage, "container %v runs %v, want %s", container["name"], container["image"], nodeAgentImage)
			for _, m := range container["volumeMounts"].([]any) {
				mounts[container["name"].(string)] = append(mounts[container["name"].(string)], m.(map[string]any)["name"].(string))
			}
		}
	}
	testutil.FailIf(t, !slicesEqualSet(mounts["report"], "host-evidence", "report-token", "api-token", "tmp"), "the report container mounts %v", mounts["report"])
	testutil.FailIf(t, !slicesEqualSet(mounts["host"], "host-evidence"), "the host container mounts %v, want only host-evidence, so it holds no token of its own", mounts["host"])
}

// kubectl skips the in-cluster config whenever a flag such as --request-timeout
// overrides it and no kubeconfig file exists, and dials localhost:8080 instead.
func TestNodeAgentSeed_EveryKubectlContainerNamesTheImagesInClusterKubeconfig(t *testing.T) {
	const kubeconfigPath = "/opt/mitstack/in-cluster.kubeconfig"
	const tokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	kubeconfigEnv := map[string]string{}
	for _, doc := range nodeAgentDocs(t) {
		spec, _ := testutil.Dig(doc, "spec", "template", "spec").(map[string]any)
		if doc["kind"] == "CronJob" {
			spec, _ = testutil.Dig(doc, "spec", "jobTemplate", "spec", "template", "spec").(map[string]any)
		}
		if spec == nil {
			continue
		}
		for _, c := range spec["containers"].([]any) {
			container := c.(map[string]any)
			env, _ := container["env"].([]any)
			for _, e := range env {
				if e.(map[string]any)["name"] == "KUBECONFIG" {
					kubeconfigEnv[container["name"].(string)] = e.(map[string]any)["value"].(string)
				}
			}
		}
	}
	for _, name := range []string{"report", "refresh"} {
		testutil.FailIf(t, kubeconfigEnv[name] != kubeconfigPath, "the %s container runs kubectl with KUBECONFIG %q, want %s", name, kubeconfigEnv[name], kubeconfigPath)
	}
	_, hostHasOne := kubeconfigEnv["host"]
	testutil.FailIf(t, hostHasOne, "the host container sets KUBECONFIG, which k3s kubectl would follow in the host's namespaces instead of k3s's admin config")

	dockerfile := testutil.TestRepoFile(t, "scripts/nodeagent/Dockerfile")
	testutil.FailIf(t, !strings.Contains(dockerfile, "scripts/nodeagent/in-cluster.kubeconfig "+kubeconfigPath), "the node-agent image does not copy scripts/nodeagent/in-cluster.kubeconfig to %s", kubeconfigPath)

	kubeconfig := testutil.YamlMap(t, "in-cluster.kubeconfig", testutil.TestRepoFile(t, "scripts/nodeagent/in-cluster.kubeconfig"))
	cluster, _ := testutil.Dig(kubeconfig, "clusters").([]any)
	user, _ := testutil.Dig(kubeconfig, "users").([]any)
	testutil.FatalIf(t, len(cluster) != 1 || len(user) != 1, "in-cluster.kubeconfig names %d clusters and %d users, want one of each", len(cluster), len(user))
	testutil.FailIf(t, testutil.Dig(cluster[0], "cluster", "server") != "https://kubernetes.default.svc" || testutil.Dig(cluster[0], "cluster", "certificate-authority") != tokenDir+"/ca.crt",
		"in-cluster.kubeconfig's cluster is %v, want https://kubernetes.default.svc verified by %s/ca.crt", cluster[0], tokenDir)
	testutil.FailIf(t, testutil.Dig(user[0], "user", "tokenFile") != tokenDir+"/token", "in-cluster.kubeconfig's user is %v, want tokenFile %s/token, which kubectl rereads as the kubelet rotates it", user[0], tokenDir)
	testutil.FailIf(t, kubeconfig["current-context"] == nil || kubeconfig["current-context"] == "", "in-cluster.kubeconfig names no current-context")
}

func TestNodeAgentSeed_TheProbeJobAsksForTheUserDataAt0_2And10SecondsAndDiscardsIt(t *testing.T) {
	var command []string
	for _, doc := range nodeAgentDocs(t) {
		if doc["kind"] == "Job" {
			for _, part := range testutil.Dig(doc, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)["command"].([]any) {
				command = append(command, part.(string))
			}
		}
	}
	testutil.FatalIf(t, len(command) == 0, "the seed holds no metadata probe Job with a command")

	runProbePodCommand(t, command)
}

func slicesEqualSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

var probeLineRe = regexp.MustCompile(`^t=([0-9]+)s (.+): http=([0-9]{3}) bytes=([0-9]+)$`)

func runProbePodCommand(t *testing.T, command []string) {
	t.Helper()
	userData := servedUserData(t, testutil.FixtureEnrolmentToken)
	curl := newFakeCurl(t, userData)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = []string{"PATH=" + curl.dir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	err := cmd.Run()
	output := stdout.String() + stderr.String()
	testutil.FatalIf(t, ctx.Err() != nil, "the probe pod's command %q did not finish within 30s:\n%s", command, output)
	testutil.FailIf(t, err != nil, "the probe pod's command exited %v, want 0 however its requests end, so the pod succeeds:\n%s", err, output)
	attempts := curl.attempts(t)
	testutil.FatalIf(t, len(attempts) != 3, "the probe pod's command ran curl %d times, want 3:\n%s", len(attempts), output)
	offsets := []struct{ lo, hi float64 }{{0, 1.5}, {1.0, 3.5}, {9.0, 12}}
	for i, a := range attempts {
		at := a.At - float64(start.UnixNano())/1e9
		testutil.FailIf(t, at < offsets[i].lo || at >= offsets[i].hi, "request %d went %.2fs after the command started, want %.1fs to %.1fs", i+1, at, offsets[i].lo, offsets[i].hi)
		silent := slices.Contains(a.Argv, "-sS") || slices.Contains(a.Argv, "-Ss") ||
			((slices.Contains(a.Argv, "-s") || slices.Contains(a.Argv, "--silent")) && (slices.Contains(a.Argv, "-S") || slices.Contains(a.Argv, "--show-error")))
		testutil.FailIf(t, !slices.Contains(a.Argv, metadataProbeUserDataURL) || !silent, "request %d ran curl with %q, want -sS and %s", i+1, a.Argv, metadataProbeUserDataURL)
		for _, p := range []struct {
			value string
			flags []string
		}{{"/dev/null", []string{"-o", "--output"}}, {"1", []string{"--connect-timeout"}}, {"2", []string{"--max-time", "-m"}}, {"http=%{http_code} bytes=%{size_download}", []string{"-w", "--write-out"}}} {
			testutil.FailIf(t, !hasPair(a.Argv, p.value, p.flags...), "request %d ran curl with %q, want %s %q", i+1, a.Argv, p.flags[0], p.value)
		}
	}
	var lines [][]string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if m := probeLineRe.FindStringSubmatch(line); m != nil {
			lines = append(lines, m)
		}
	}
	want := []struct{ at, code, size string }{{"0", "200", strconv.Itoa(len(userData))}, {"2", "000", "0"}, {"10", "000", "0"}}
	testutil.FatalIf(t, len(lines) != len(want), "the probe pod printed %d attempt lines shaped t=<n>s <UTC time>: http=<code> bytes=<n>, want %d:\n%s", len(lines), len(want), output)
	for i, w := range want {
		m := lines[i]
		testutil.FailIf(t, m[1] != w.at || m[3] != w.code || m[4] != w.size || !regexp.MustCompile(`[0-9]{2}:[0-9]{2}:[0-9]{2}`).MatchString(m[2]), "attempt line %d = %q, want t=%ss, a UTC time, http=%s and bytes=%s", i+1, m[0], w.at, w.code, w.size)
	}
	testutil.AssertNamesAll(t, "the probe pod's output", output, "curl: (28) Connection timed out")
	for _, leaked := range []string{testutil.FixtureEnrolmentToken, "#cloud-config", "MITSTACK_ENROLMENT_TOKEN"} {
		testutil.FailIf(t, strings.Contains(output, leaked), "the probe pod's output carries %q from the user data it requested", leaked)
	}
}

func hasPair(argv []string, value string, flags ...string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if slices.Contains(flags, argv[i]) && argv[i+1] == value {
			return true
		}
	}
	return false
}
