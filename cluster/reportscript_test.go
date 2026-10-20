package cluster

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	reportJournalLimit    = 500
	reportCloudInitLimit  = 300
	reportBodyLimit       = 256 * 1024
	reportBodyMax         = reportBodyLimit - 1
	osReleaseLimit        = 4096
	kubernetesStderrLimit = 4096
	redactedValue         = "<redacted>"
	reportCloudInitBudget = 24000
	reportJournalBudget   = 90000

	secretsEncryptionLimit = 2048
	ciliumStatusLimit      = 4096
	hubbleObserveLimit     = 8192
	listenersLimit         = 8192
	sshUnitsLimit          = 1024
	metadataGuardLimit     = 2048
	metadataProbeLogLimit  = 4096

	patchCheckFileLimit        = 4096
	autoUpgradeUnitsLimit      = 1024
	unattendedUpgradesLogLimit = 3072
	rebootPackagesLimit        = 1024
	kuredLogLimit              = 4096
	upgradePlansLimit          = 1536
	upgradeJobsLimit           = 1536

	admissionFixtureLimit      = 4096
	admissionMessageLimit      = 2048
	defaultDenyLimit           = 4096
	admissionNamespace         = "mitstack-admission-probe"
	dryRunOutputLimit          = 8192
	podSecurityLimit           = 4096
	subscriptionResourcesLimit = 8192
	cloudNativePGLimit         = 4096
	labelledRowCost            = 128
	jwksLimit                  = 4096
	jwksUnreadable             = "k3s kubectl exited 0, and its output is not the key set JSON this report reads"
	argocdListLimit            = 4096

	applicationsLimit                = 24000
	applicationConditionMessageLimit = 512
)

var (
	reportBodyKeys = []string{
		"admission", "appProjects", "applications", "argocd", "bootId", "certificates", "challenges", "ciliumPods", "cloudInit", "cloudNativePG", "dedicatedServer", "defaultDenyPolicies", "enrolment", "enrolmentReuse", "hardening", "helmCharts",
		"helmInstallJobs", "journal", "jwks", "kubernetes", "madeAt", "osRelease", "patching", "podMemory", "podSecurity",
		"podSecurityDryRun", "repositorySecrets", "securityScans", "subscriptionResources", "subscriptionResourcesComplete",
	}
	hardeningKeys = []string{"ciliumStatus", "hubbleObserve", "kubelet", "listeners", "metadataGuard", "metadataProbe", "secretsEncryption", "sshUnits"}
	patchingKeys  = []string{"autoUpgradeUnits", "check", "kured", "rebootRequired", "unattendedUpgradesLog", "upgradePlans"}

	patchingMemberBounds = map[string]int{
		"check": 4608, "autoUpgradeUnits": 1024, "unattendedUpgradesLog": 3072, "rebootRequired": 1536, "kured": 8704, "upgradePlans": 3584,
	}
	patchingPartBounds = map[string]int{"kured.current": 4096, "kured.previous": 4096, "upgradePlans.plans": 1536, "upgradePlans.jobs": 1536}

	largestToolOutput    = strings.Repeat("\"\x01", 1<<17)
	servedEnrolmentToken = strings.Repeat("c0ffee", 10) + "c0ff"
	madeAtShape          = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

	reportJournalArgs = []string{
		"-b", "--no-pager", "-o", "short-iso-precise",
		"_SYSTEMD_UNIT=mitstack-enrol.service", "+", "_PID=1", "UNIT=mitstack-enrol.service", "+", "_PID=1", "UNIT=k3s.service", "+",
		"_SYSTEMD_UNIT=mitstack-repo-token.service", "+", "_PID=1", "UNIT=mitstack-metadata-guard.service", "+",
		"_SYSTEMD_UNIT=mitstack-metadata-guard.service",
	}

	wantClusterFields = map[string]string{
		"ciliumPods": "want/cilium-pods.json", "helmInstallJobs": "want/helm-install-jobs.json", "helmCharts": "want/helm-charts.json",
		"applications": "want/applications.json", "repositorySecrets": "want/repository-secrets.json", "podMemory": "want/pod-memory.json",
		"podSecurity": "want/pod-security.json", "subscriptionResources": "want/subscription-resources.json", "jwks": "k3s/jwks.json",
		"admission": "want/admission.json", "defaultDenyPolicies": "want/default-deny-policies.json",
		"certificates": "want/certificates.json", "challenges": "want/challenges.json", "appProjects": "want/app-projects.json",
		"cloudNativePG": "want/cloudnative-pg.json",
	}
)

type hardeningCommand struct {
	field, canned string
	limit, exit   int
}

var hardeningCommands = []hardeningCommand{
	{"secretsEncryption", "report/secrets-encrypt-status.txt", secretsEncryptionLimit, 0},
	{"ciliumStatus", "report/cilium-status.txt", ciliumStatusLimit, 0},
	{"hubbleObserve", "report/hubble-observe.txt", hubbleObserveLimit, 0},
	{"listeners", "report/listeners.txt", listenersLimit, 0},
	{"sshUnits", "", sshUnitsLimit, 1},
	{"metadataGuard", "report/metadata-guard.txt", metadataGuardLimit, 0},
}

func (c hardeningCommand) cannedOutput() string {
	if c.canned == "" {
		return cannedSSHUnits
	}
	return testFile(c.canned)
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func mapKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func jsonTextLen(s string) int {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
	return b.Len() - 3
}

func decodeAny(t *testing.T, what string, raw []byte) any {
	t.Helper()
	var v any
	err := json.Unmarshal(raw, &v)
	fatalIf(t, err != nil, "%s is not JSON: %v\n%s", what, err, truncate(string(raw), 300))
	return v
}

func sameJSON(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	failIf(t, !reflect.DeepEqual(decodeAny(t, what, got), decodeAny(t, "the want for "+what, []byte(want))), "%s = %s\nwant exactly %s", what, truncate(string(got), 600), truncate(want, 600))
}

func objectOf(t *testing.T, what string, raw []byte, keys ...string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	err := json.Unmarshal(raw, &m)
	fatalIf(t, err != nil || m == nil, "%s = %s, want an object of %v", what, truncate(string(raw), 300), keys)
	got, want := mapKeys(m), slices.Sorted(slices.Values(keys))
	failIf(t, !slices.Equal(got, want), "%s has keys %v, want exactly %v", what, got, want)
	return m
}

func stringOf(t *testing.T, what string, raw []byte) string {
	t.Helper()
	var s string
	err := json.Unmarshal(raw, &s)
	fatalIf(t, err != nil, "%s = %s, want a string", what, truncate(string(raw), 300))
	failIf(t, strings.ContainsRune(s, 0), "%s carries a NUL", what)
	return s
}

func reportFields(t *testing.T, req recordedEnrolRequest) map[string]json.RawMessage {
	t.Helper()
	return objectOf(t, "the report body", req.Body, reportBodyKeys...)
}

func postedReport(t *testing.T, req recordedEnrolRequest) (bootID, journal string) {
	t.Helper()
	fields := reportFields(t, req)
	return stringOf(t, "bootId", fields["bootId"]), stringOf(t, "journal", fields["journal"])
}

func assertNoNUL(t *testing.T, from string, body []byte) {
	t.Helper()
	failIf(t, strings.Contains(strings.ToLower(string(body)), `\u0000`) || bytes.ContainsRune(body, 0), "the report body carries a NUL from %s", from)
}

func assertUTCWithin(t *testing.T, v any, start, end time.Time) {
	t.Helper()
	s, ok := v.(string)
	if !ok || !madeAtShape.MatchString(s) {
		t.Errorf("time = %#v, want a UTC time written YYYY-MM-DDTHH:MM:SSZ", v)
		return
	}
	at, err := time.Parse(time.RFC3339, s)
	failIf(t, err != nil || at.Before(start.Truncate(time.Second).Add(-time.Second)) || at.After(end.Add(time.Second)), "time %s (parse err %v) is outside the run, %s to %s", s, err, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

func assertNonEmptyList(t *testing.T, what string, raw []byte) {
	t.Helper()
	var items []json.RawMessage
	err := json.Unmarshal(raw, &items)
	failIf(t, err != nil || len(items) == 0, "%s = %s, want a list holding entries after a read that succeeded", what, truncate(string(raw), 200))
}

func assertKubectlFailure(t *testing.T, what string, got []byte, exit int, message string) {
	t.Helper()
	f := objectOf(t, what, got, "exitStatus", "stderr")
	var status int
	err := json.Unmarshal(f["exitStatus"], &status)
	failIf(t, err != nil, "%s.exitStatus = %s, want a number", what, f["exitStatus"])
	failIf(t, (exit >= 0 && status != exit) || (exit < 0 && status == 0), "%s.exitStatus = %d, want %d (any non-zero if negative)", what, status, exit)
	stderr := stringOf(t, what+".stderr", f["stderr"])
	failIf(t, strings.TrimSpace(stderr) == "" || len(stderr) > kubernetesStderrLimit || !strings.Contains(stderr, message), "%s.stderr = %q (%d bytes), want 1 to %d bytes of the failed read's stderr carrying %q", what, truncate(stderr, 200), len(stderr), kubernetesStderrLimit, message)
}

func commandResult(t *testing.T, what string, raw []byte, limit int) (int, string) {
	t.Helper()
	m := objectOf(t, what, raw, "exitStatus", "output")
	var status int
	err := json.Unmarshal(m["exitStatus"], &status)
	failIf(t, err != nil, "%s.exitStatus = %s, want a number", what, m["exitStatus"])
	output := stringOf(t, what+".output", m["output"])
	n := jsonTextLen(output)
	failIf(t, n > limit, "%s.output is %d bytes of JSON text, want at most %d", what, n, limit)
	return status, output
}

func assertCommandAnswered(t *testing.T, c hardeningCommand, hardening map[string]json.RawMessage) {
	t.Helper()
	status, output := commandResult(t, "hardening."+c.field, hardening[c.field], c.limit)
	want := strings.TrimRight(c.cannedOutput(), "\n")
	failIf(t, status != c.exit || !strings.Contains(output, want), "hardening.%s = exitStatus %d, output %q, want %d and output carrying %q", c.field, status, truncate(output, 300), c.exit, want)
}

func assertClusterField(t *testing.T, field string, got []byte) {
	t.Helper()
	g, w := decodeAny(t, field, got), decodeAny(t, "the want for "+field, []byte(testFile(wantClusterFields[field])))
	switch field {
	case "repositorySecrets", "podSecurity", "appProjects":
		g, w = sortedBy(g, "name"), sortedBy(w, "name")
	case "subscriptionResources":
		g, w = sortedBy(g, "namespace", "kind", "name"), sortedBy(w, "namespace", "kind", "name")
	}
	failIf(t, !reflect.DeepEqual(g, w), "%s = %s\nwant exactly %s", field, truncate(string(got), 600), truncate(testFile(wantClusterFields[field]), 600))
}

func sortedBy(v any, members ...string) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	key := func(e any) string {
		m, _ := e.(map[string]any)
		var parts []string
		for _, member := range members {
			s, _ := m[member].(string)
			parts = append(parts, s)
		}
		return strings.Join(parts, "\x00")
	}
	out := slices.Clone(items)
	slices.SortFunc(out, func(a, b any) int { return strings.Compare(key(a), key(b)) })
	return out
}

type clusterRead struct{ read, field, part string }

var clusterReads = []clusterRead{
	{readKubeSystem, "ciliumPods", ""}, {readJobs, "helmInstallJobs", ""}, {readHelmCharts, "helmCharts", ""},
	{readApplications, "applications", ""}, {readSecrets, "repositorySecrets", ""}, {readArgoCDMetrics, "podMemory", "argocd"},
	{readCiliumMetrics, "podMemory", "cilium"}, {readNamespaces, "podSecurity", ""}, {readSubscriptionResources, "subscriptionResources", ""},
	{readJWKS, "jwks", ""}, {readAdmissionFixtures, "admission", ""}, {readDefaultDeny, "defaultDenyPolicies", ""},
	{readCertificates, "certificates", ""}, {readChallenges, "challenges", ""}, {readAppProjects, "appProjects", ""},
	{readCloudNativePG, "cloudNativePG", ""},
}

func (r clusterRead) name() string { return strings.TrimSuffix(r.field+"."+r.part, ".") }

func (r clusterRead) in(t *testing.T, fields map[string]json.RawMessage) []byte {
	t.Helper()
	if r.part == "" {
		return fields[r.field]
	}
	return objectOf(t, r.field, fields[r.field], "argocd", "cilium")[r.part]
}

func dryRunResult(t *testing.T, raw []byte) (int, string) {
	t.Helper()
	m := objectOf(t, "podSecurityDryRun", raw, "exitStatus", "output")
	var status int
	var output string
	failIf(t, json.Unmarshal(m["exitStatus"], &status) != nil || json.Unmarshal(m["output"], &output) != nil || len(output) > dryRunOutputLimit, "podSecurityDryRun = %s, want a numeric exitStatus and output of at most %d bytes", truncate(string(raw), 200), dryRunOutputLimit)
	return status, output
}

func assertDryRunAnswered(t *testing.T, raw []byte) {
	t.Helper()
	status, output := dryRunResult(t, raw)
	failIf(t, status != 0, "podSecurityDryRun.exitStatus = %d, want 0", status)
	for _, line := range strings.Split(strings.TrimSpace(testFile("report/dry-run-stdout.txt")+testFile("report/dry-run-stderr.txt")), "\n") {
		failIf(t, !strings.Contains(output, line), "podSecurityDryRun.output = %q, want it to carry %q", truncate(output, 300), line)
	}
}

func assertClusterAnsweredBut(t *testing.T, fields map[string]json.RawMessage, skip clusterRead) {
	t.Helper()
	if skip.field != "kubernetes" {
		sameJSON(t, "kubernetes", fields["kubernetes"], testFile("want/kubernetes.json"))
	}
	if skip.field != "podSecurityDryRun" {
		assertDryRunAnswered(t, fields["podSecurityDryRun"])
	}
	for _, field := range mapKeys(wantClusterFields) {
		switch {
		case field == skip.field && field == "podMemory":
			parts := objectOf(t, "podMemory", fields[field], "argocd", "cilium")
			wantParts := objectOf(t, "the want for podMemory", []byte(testFile(wantClusterFields[field])), "argocd", "cilium")
			for _, part := range mapKeys(wantParts) {
				if part != skip.part {
					sameJSON(t, "podMemory."+part, parts[part], string(wantParts[part]))
				}
			}
		case field != skip.field:
			assertClusterField(t, field, fields[field])
		}
	}
}

func assertMadeAt(t *testing.T, fields map[string]json.RawMessage, notBefore, notAfter time.Time) time.Time {
	t.Helper()
	s := stringOf(t, "madeAt", fields["madeAt"])
	at, err := time.Parse(time.RFC3339, s)
	failIf(t, !madeAtShape.MatchString(s) || err != nil || at.Before(notBefore.Truncate(time.Second)) || at.After(notAfter), "madeAt = %q (parse err %v), want a UTC second within the run, %s to %s", s, err, notBefore.UTC().Format(time.RFC3339Nano), notAfter.UTC().Format(time.RFC3339Nano))
	return at
}

type k3sCall struct {
	argv       []string
	verb       string
	positional []string
	flags      map[string]string
	command    []string
	hasCommand bool
}

var kubectlValueFlags = map[string]string{
	"-n": "--namespace", "--namespace": "--namespace", "-c": "--container", "--container": "--container", "-o": "--output", "--output": "--output",
	"-l": "--selector", "--selector": "--selector", "--image": "--image", "--restart": "--restart", "--raw": "--raw", "--for": "--for",
	"--timeout": "--timeout", "--request-timeout": "--request-timeout", "--tail": "--tail", "--limit-bytes": "--limit-bytes", "--since": "--since",
	"--since-time": "--since-time", "-f": "--filename", "--filename": "--filename", "--field-selector": "--field-selector", "-L": "--label-columns", "--label-columns": "--label-columns", "--sort-by": "--sort-by", "--template": "--template",
}

func parseK3sCalls(argvs [][]string) []k3sCall {
	calls := make([]k3sCall, 0, len(argvs))
	for _, argv := range argvs {
		c := k3sCall{argv: argv, flags: map[string]string{}}
		if len(argv) == 0 || argv[0] != "kubectl" {
			c.verb = strings.Join(argv, " ")
			calls = append(calls, c)
			continue
		}
		head := argv[1:]
		if i := slices.Index(head, "--"); i >= 0 {
			c.command, c.hasCommand, head = head[i+1:], true, head[:i]
		}
		for i := 0; i < len(head); i++ {
			a := head[i]
			if name, ok := kubectlValueFlags[a]; ok && i+1 < len(head) {
				c.flags[name] = head[i+1]
				i++
			} else if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "--") {
				c.flags[cmpFlag(k)] = v
			} else if len(a) > 2 && strings.Contains("-n -c -o -l", a[:2]) && kubectlValueFlags[a[:2]] != "" {
				c.flags[kubectlValueFlags[a[:2]]] = strings.TrimPrefix(a[2:], "=")
			} else if strings.HasPrefix(a, "-") {
				c.flags[a] = ""
			} else {
				c.positional = append(c.positional, a)
			}
		}
		if len(c.positional) > 0 {
			c.verb = c.positional[0]
		}
		calls = append(calls, c)
	}
	return calls
}

func cmpFlag(k string) string {
	if name, ok := kubectlValueFlags[k]; ok {
		return name
	}
	return k
}

func (c k3sCall) line() string { return strings.Join(c.argv, " ") }

func (c k3sCall) names(name string, types ...string) bool {
	obj := c.positional[min(1, len(c.positional)):]
	if len(obj) == 1 {
		if typ, n, ok := strings.Cut(obj[0], "/"); ok {
			obj = []string{typ, n}
		}
	}
	return len(obj) == 2 && slices.Contains(types, obj[0]) && obj[1] == name
}

func (c k3sCall) resources() []string {
	if len(c.positional) < 2 {
		return nil
	}
	return strings.Split(c.positional[1], ",")
}

func k3sCallsOf(t *testing.T, k fakeK3s) []k3sCall {
	t.Helper()
	return parseK3sCalls(k.argvs(t))
}

type reportCase struct {
	name   string
	opts   []reportOption
	manual bool // the check runs the script itself
	check  func(t *testing.T, r *reportRig)
}

func runReportCases(t *testing.T, cases []reportCase) {
	t.Helper()
	t.Parallel()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := newReportRig(t, c.opts...)
			if !c.manual {
				r.send()
			}
			c.check(t, r)
		})
	}
}

func TestReportScript_Contract(t *testing.T) {
	host, collect, report := testRepoFile(t, "scripts/nodeagent/host.sh"), testRepoFile(t, "scripts/nodeagent/collect.sh"), testRepoFile(t, "scripts/nodeagent/report.sh")
	for what, script := range map[string]string{"host.sh": host, "collect.sh": collect, "report.sh": report} {
		failIf(t, !shebangRe.MatchString(firstLine(script)), "%s starts with %q, want a POSIX sh shebang such as #!/bin/sh", what, firstLine(script))
		failIf(t, jqRe.MatchString(script), "%s runs jq, which neither the image nor stock ubuntu-24.04 has", what)
		failIf(t, strings.Contains(script, "hetzner/v1/metadata"), "%s reads hetzner/v1/metadata; the report reads only the user data, and the node script alone reads the metadata", what)
	}
	assertTokenOffCurlLines(t, "collect.sh", collect, "TOKEN")
	assertTokenOffCurlLines(t, "report.sh", report, "token")
	// The tests override every default below, so only the source shows what a node uses.
	assertNamesAll(t, "host.sh", host, "/run/mitstack-host")
	assertNamesAll(t, "collect.sh", collect, "/etc/mitstack", "/etc/os-release", "/var/log/cloud-init-output.log", "http://169.254.169.254"+userDataPath,
		"https://api.mitstack.dev"+enrolEndpointPath, "/var/lib/mitstack", "/var/log/unattended-upgrades/unattended-upgrades.log", "/var/run/reboot-required")
	assertNamesAll(t, "report.sh", report, "https://api.mitstack.dev"+reportEndpointPath, "/var/run/mitstack/token", "/run/mitstack-host")
}

func TestReportScript_Delivery(t *testing.T) {
	longJournal := make([]string, 600)
	for i := range longJournal {
		longJournal[i] = "2026-10-01T09:00:00.000000+00:00 orbitdemo-abcd2345 systemd[1]: line " + strconv.Itoa(i+1)
	}
	cases := []reportCase{
		{name: "posts the boot id and the journal with the report token", check: func(t *testing.T, r *reportRig) {
			req := r.req
			failIf(t, req.Method != http.MethodPost || req.Path != reportEndpointPath || req.ContentType != "application/json", "the request was %s %s as %q, want POST %s as application/json", req.Method, req.Path, req.ContentType, reportEndpointPath)
			want := "Bearer " + fixtureReportToken
			failIf(t, req.Authorization != want, "the Authorization header is not Bearer and the reportToken from %s (%d characters received)", enrolScriptJSONFile, len(req.Authorization))
			boot, journal := postedReport(t, req)
			raw, err := os.ReadFile(bootIDPath)
			failIf(t, err != nil || boot != strings.TrimSpace(string(raw)), "bootId = %q, want %q from %s (read err %v)", boot, raw, bootIDPath, err)
			want2 := strings.Join(cannedJournal, "\n")
			failIf(t, strings.TrimRight(journal, "\n") != want2, "journal = %q\nwant      %q", journal, want2)
		}},
		{name: "reads this boot's journal of the enrol, repo-token, k3s and metadata guard units", check: func(t *testing.T, r *reportRig) {
			args := r.jctl.args(t)
			fatalIf(t, args == nil, "the report script never ran %s\n%s", reportJournalctlEnv, r.run.output())
			limit := strconv.Itoa(reportJournalLimit)
			var filter []string
			for i := 0; i < len(args); i++ {
				switch a := args[i]; {
				case (a == "-n" || a == "--lines") && i+1 < len(args) && args[i+1] == limit:
					i++
				case a == "-n"+limit || a == "--lines="+limit:
				default:
					filter = append(filter, a)
				}
			}
			failIf(t, !slices.Equal(filter, reportJournalArgs), "journalctl ran with %q\nwant              %q (and optionally -n %d)", args, reportJournalArgs, reportJournalLimit)
		}},
		{name: "sends only the last 500 journal lines", opts: []reportOption{withJournal(longJournal)}, check: func(t *testing.T, r *reportRig) {
			_, got := postedReport(t, r.req)
			gotLines, want := strings.Split(strings.TrimRight(got, "\n"), "\n"), longJournal[len(longJournal)-reportJournalLimit:]
			failIf(t, !slices.Equal(gotLines, want), "the journal carries %d lines from %q to %q, want the last %d, %q to %q",
				len(gotLines), gotLines[0], gotLines[len(gotLines)-1], reportJournalLimit, want[0], want[len(want)-1])
		}},
		{name: "keeps no token in its output, on a command line or under TMPDIR", opts: []reportOption{recording()}, check: func(t *testing.T, r *reportRig) {
			assertQuietRun(t, "the report script", r.run, r.rec, r.srv.received())
		}},
	}
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
		cases = append(cases, reportCase{name: "exits 0 on a " + strconv.Itoa(status), opts: []reportOption{withPlatform(status)}, check: func(t *testing.T, r *reportRig) {
			n := len(r.srv.received())
			failIf(t, n != 1, "the report script sent %d requests answered %d, want exactly one", n, status)
		}})
	}
	for _, status := range []int{401, 404, 429, 500, 503} {
		why := "a " + strconv.Itoa(status)
		cases = append(cases, reportCase{name: "exits non-zero on " + why + " after one attempt", opts: []reportOption{withPlatform(status)}, manual: true, check: func(t *testing.T, r *reportRig) {
			assertExitedNonZero(t, why, r.exec())
			n := len(r.srv.received())
			failIf(t, n != 1, "the report script sent %d requests on %s, want exactly one: it does not retry", n, why)
		}})
	}
	cases = append(cases, reportCase{name: "exits non-zero on a connection failure", opts: []reportOption{unreachablePlatform()}, manual: true, check: func(t *testing.T, r *reportRig) {
		assertExitedNonZero(t, "a connection failure", r.exec())
	}})
	for _, tc := range []struct{ name, token string }{
		{"an empty report token", ""},
		{"a report token of two lines", fixtureReportToken + "\n" + fixtureReportToken},
	} {
		cases = append(cases, reportCase{name: "fails with " + tc.name + " and sends nothing", opts: []reportOption{withToken(tc.token)}, manual: true, check: func(t *testing.T, r *reportRig) {
			assertExitedNonZero(t, tc.name, r.exec())
			n := len(r.srv.received())
			failIf(t, n != 0, "the report script sent %d requests with %s, want none", n, tc.name)
		}})
	}
	cases = append(cases, reportCase{name: "fails with no enrolment.json and sends nothing", opts: []reportOption{withEmptyDir()}, manual: true, check: func(t *testing.T, r *reportRig) {
		assertExitedNonZero(t, "no enrolment.json", r.exec())
		n := len(r.srv.received())
		failIf(t, n != 0, "the report script sent %d requests with no enrolment.json, want none", n)
	}})
	runReportCases(t, cases)
}

func TestReportScript_RefusesAHostArchiveOlderThanFifteenMinutes(t *testing.T) {
	srv := newFakeEnrolment(t, fixtureReportToken, http.StatusOK)
	hostDir := t.TempDir()
	old := time.Now().Add(-16 * time.Minute)
	fatalIf(t, os.Chtimes(writeIn(t, hostDir, "host.tar", "", 0o644), old, old) != nil, "ageing host.tar")
	env := []string{reportScriptURLEnv + "=" + srv.URL + reportEndpointPath, hostDirEnv + "=" + hostDir, tokenFileEnv + "=" + writeIn(t, t.TempDir(), "token", fixtureReportToken, 0o600)}

	run := runShFile(t, "report", filepath.Join(nodeAgentDir(t), "mitstack-report"), reportRunBound, enrolRun{tmp: t.TempDir()}, env, srv.caFile, nil)

	assertExitedNonZero(t, "a 16-minute-old host.tar", run)
	failIf(t, len(srv.received()) != 0 || !strings.Contains(run.stderr, "older than 15 minutes"), "the report sent %d reports and printed %q, want none and why", len(srv.received()), run.stderr)
}

func TestReportScript_NodeEvidence(t *testing.T) {
	cloudInit := make([]string, 400)
	for i := range cloudInit {
		cloudInit[i] = fmt.Sprintf("Cloud-init v. 25.1.4 output line %d", i+1)
	}
	cloudInit[350] = "mitstack-enrol: the platform said \"busy\" \\ retrying\tin 1s"
	const before, after = "text-before-the-nul", "text-after-the-nul"
	nul := before + "\x00" + after
	cases := []reportCase{
		{name: "carries os-release verbatim", check: func(t *testing.T, r *reportRig) {
			got := stringOf(t, "osRelease", reportFields(t, r.req)["osRelease"])
			failIf(t, strings.TrimRight(got, "\n") != strings.TrimRight(testFile("report/os-release"), "\n"), "osRelease = %q\nwant the text of os-release", got)
		}},
		{name: "carries the last 300 lines of the cloud-init output log", opts: []reportOption{withSource(reportCloudInitLogEnv, "cloud-init-output.log", strings.Join(cloudInit, "\n")+"\n")}, check: func(t *testing.T, r *reportRig) {
			got := strings.Split(strings.TrimRight(stringOf(t, "cloudInit", reportFields(t, r.req)["cloudInit"]), "\n"), "\n")
			want := cloudInit[len(cloudInit)-reportCloudInitLimit:]
			failIf(t, !slices.Equal(got, want), "cloudInit carries %d lines from %q to %q, want the last %d, %q to %q", len(got), got[0], got[len(got)-1], reportCloudInitLimit, want[0], want[len(want)-1])
		}},
		{name: "still reports without a cloud-init output log", opts: []reportOption{withEnvVar(reportCloudInitLogEnv, "/nonexistent/cloud-init-output.log")}, check: func(t *testing.T, r *reportRig) {
			stringOf(t, "cloudInit", reportFields(t, r.req)["cloudInit"])
		}},
		{name: "carries what k3s kubectl reads of the nodes and the Argo CD pods", check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			sameJSON(t, "kubernetes", fields["kubernetes"], testFile("want/kubernetes.json"))
			var nodes struct {
				Nodes []map[string]json.RawMessage `json:"nodes"`
			}
			var served struct {
				Items []struct {
					Status map[string]json.RawMessage `json:"status"`
				} `json:"items"`
			}
			err := json.Unmarshal(fields["kubernetes"], &nodes)
			fatalIf(t, err != nil || len(nodes.Nodes) != 1, "kubernetes = %s, want one node", truncate(string(fields["kubernetes"]), 300))
			err2 := json.Unmarshal([]byte(testFile("k3s/nodes.json")), &served)
			fatalIf(t, err2 != nil, "the served nodes: %v", err2)
			for _, key := range []string{"capacity", "allocatable"} {
				sameJSON(t, "kubernetes.nodes[0]."+key, nodes.Nodes[0][key], string(served.Items[0].Status[key]))
			}
			for _, call := range r.k3s.calls(t) {
				failIf(t, !strings.HasPrefix(call, "kubectl ") && call != "secrets-encrypt status", "k3s ran with %q, want only k3s kubectl and k3s secrets-encrypt status", call)
				failIf(t, strings.Contains(strings.ToLower(call), "kubeconfig"), "k3s kubectl ran with %q; as root it reads k3s's own admin config, and the report names no kubeconfig", call)
			}
		}},
		{name: "enrolment carries only field names with every value redacted", check: func(t *testing.T, r *reportRig) {
			want := map[string]any{"repositoryToken": redactedValue, "repositoryTokenExpiresAt": redactedValue, "reportToken": redactedValue, "notificationToken": redactedValue}
			got := decodeAny(t, "enrolment", reportFields(t, r.req)["enrolment"])
			failIf(t, !reflect.DeepEqual(got, want), "enrolment = %v, want %v", got, want)
		}},
		{name: "enrolment redacts the values of an answer with more fields", opts: []reportOption{withAnswer(enrolAnswer(t, map[string]any{
			"repositoryToken": fixtureRepositoryToken, "repositoryTokenExpiresAt": fixtureRepositoryTokenExpiresAt, "reportToken": fixtureReportToken,
			"issuedAt": "2026-10-01T09:14:03Z", "expiresIn": 3600}))}, check: func(t *testing.T, r *reportRig) {
			want := map[string]any{"repositoryToken": redactedValue, "repositoryTokenExpiresAt": redactedValue, "reportToken": redactedValue, "issuedAt": redactedValue, "expiresIn": redactedValue}
			got := decodeAny(t, "enrolment", reportFields(t, r.req)["enrolment"])
			failIf(t, !reflect.DeepEqual(got, want), "enrolment = %v, want %v", got, want)
		}},
		{name: "madeAt is a UTC second within the run and no later than the report's first cluster read", opts: []reportOption{withK3s(k3sDelayingFirstCall(1100 * time.Millisecond))}, manual: true, check: func(t *testing.T, r *reportRig) {
			start := time.Now()
			r.send()
			madeAt := assertMadeAt(t, reportFields(t, r.req), start, time.Now())
			argvs, times := r.k3s.argvs(t), r.k3s.callTimes(t)
			fatalIf(t, len(times) == 0 || len(times) != len(argvs), "the fake k3s recorded %d calls and %d call times, want one time for each call", len(argvs), len(times))
			first := slices.IndexFunc(argvs, func(argv []string) bool {
				return len(argv) > 2 && slices.Equal(argv[:3], []string{"kubectl", "get", "nodes"})
			})
			fatalIf(t, first < 0, "the report never read the nodes")
			began := times[first].Truncate(time.Second)
			failIf(t, madeAt.After(began), "madeAt = %s, later than the report's first read, %q, which began at %s", madeAt.UTC().Format(time.RFC3339), strings.Join(argvs[first], " "), times[first].UTC().Format(time.RFC3339Nano))
		}},
	}
	for _, tc := range []struct {
		name    string
		k3s     reportOption
		message string
	}{
		{"k3s not installed", withMissingK3s(), ""},
		{"API server not up", withFailingK3s(k3sRefused + "\n"), k3sRefused},
		{"a megabyte of stderr", withFailingK3s(strings.Repeat("E", 1<<20) + "\n"), ""},
	} {
		cases = append(cases, reportCase{name: "records a k3s kubectl failure and still reports: " + tc.name, opts: []reportOption{tc.k3s}, check: func(t *testing.T, r *reportRig) {
			assertKubectlFailure(t, "kubernetes", reportFields(t, r.req)["kubernetes"], -1, tc.message)
		}})
	}
	for _, tc := range []struct{ name, stdout string }{
		{"plain text", "NAME                 STATUS   ROLES                  AGE   VERSION\norbitdemo-abcd2345   Ready    control-plane,master   5m    v1.36.3+k3s1\n"},
		{"JSON of no items", `{"apiVersion": "v1", "kind": "Status"}` + "\n"},
		{"nothing", ""},
	} {
		stdout := tc.stdout
		cases = append(cases, reportCase{name: "records k3s kubectl output that is not JSON and still reports: " + tc.name, opts: []reportOption{withPrintingK3s(stdout)}, check: func(t *testing.T, r *reportRig) {
			assertKubectlFailure(t, "kubernetes", reportFields(t, r.req)["kubernetes"], 0, "")
		}})
	}
	nulSources := []struct {
		name  string
		opts  []reportOption
		field func(t *testing.T, r *reportRig) string
	}{
		{"journal", []reportOption{withJournal(append(slices.Clone(cannedJournal), "2026-10-01T09:16:00.000000+00:00 orbitdemo-abcd2345 k3s[900]: "+nul))},
			func(t *testing.T, r *reportRig) string { _, j := postedReport(t, r.req); return j }},
		{"cloud-init output log", []reportOption{withSource(reportCloudInitLogEnv, "cloud-init-output.log", testFile("report/cloud-init-output.log")+nul+"\n")},
			func(t *testing.T, r *reportRig) string {
				return stringOf(t, "cloudInit", reportFields(t, r.req)["cloudInit"])
			}},
		{"os-release", []reportOption{withSource(reportOSReleaseEnv, "os-release", testFile("report/os-release")+"VARIANT="+nul+"\n")},
			func(t *testing.T, r *reportRig) string {
				return stringOf(t, "osRelease", reportFields(t, r.req)["osRelease"])
			}},
		{"unattended-upgrades log", []reportOption{withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", testFile("report/unattended-upgrades.log")+nul+"\n")},
			func(t *testing.T, r *reportRig) string { return patchingString(t, r, "unattendedUpgradesLog") }},
		{"reboot-required.pkgs", []reportOption{withRebootSentinel(time.Now(), nul+"\n")},
			func(t *testing.T, r *reportRig) string {
				return reportedReboot(t, patchingFields(t, r)["rebootRequired"]).Packages
			}},
		{"patch check", []reportOption{withStateDir(strings.Replace(testFile("report/patch-check.json"), `"Ubuntu 24.04.3 LTS, kernel 6.8.0-71-generic"`, `"`+before+`\u0000`+after+`"`, 1))},
			func(t *testing.T, r *reportRig) string {
				var check struct{ OS struct{ Running string } }
				err := json.Unmarshal(patchingFields(t, r)["check"], &check)
				fatalIf(t, err != nil, "patching.check is not the kept check: %v", err)
				return check.OS.Running
			}},
	}
	for _, s := range nulSources {
		cases = append(cases, reportCase{name: "a NUL byte in the " + s.name + " never reaches the body", opts: s.opts, check: func(t *testing.T, r *reportRig) {
			assertNoNUL(t, s.name, r.req.Body)
			got := s.field(t, r)
			failIf(t, !strings.Contains(got, before) || !strings.Contains(got, after), "the %s field lost the text either side of the NUL: %q", s.name, truncate(got, 200))
		}})
	}
	runReportCases(t, cases)
}

func TestReportScript_EnrolmentReuseProbe(t *testing.T) {
	setup := func(token string, userData reportOption, statuses ...int) []reportOption {
		return []reportOption{onNode(), userData, withProbe(token, statuses...)}
	}
	serving := func(token string) reportOption { return withUserData(http.StatusOK, servedUserData(t, token)) }
	reuse := func(t *testing.T, r *reportRig) map[string]any {
		t.Helper()
		m, _ := decodeAny(t, "enrolmentReuse", reportFields(t, r.req)["enrolmentReuse"]).(map[string]any)
		return m
	}
	cases := []reportCase{
		{name: "probes once with the served token and keeps the result", opts: setup(servedEnrolmentToken, serving(servedEnrolmentToken), http.StatusConflict), manual: true, check: func(t *testing.T, r *reportRig) {
			start := time.Now()
			r.send()
			end := time.Now()
			got := reuse(t, r)
			n := r.userData.hitCount(userDataPath)
			failIf(t, n != 1, "the metadata service served the user data %d times, want once", n)
			probes := r.probe.received()
			fatalIf(t, len(probes) != 1, "the enrolment endpoint received %d probes, want exactly one", len(probes))
			p := probes[0]
			failIf(t, p.Method != http.MethodPost || p.Path != enrolEndpointPath || p.ContentType != "application/json", "the probe was %s %s as %q, want POST %s as application/json", p.Method, p.Path, p.ContentType, enrolEndpointPath)
			switch p.Authorization {
			case "Bearer " + servedEnrolmentToken:
			case "Bearer " + fixtureEnrolmentToken:
				t.Error("the probe presented the token from enrolment.env, want the one the metadata service serves in the user data")
			default:
				t.Errorf("the probe's Authorization is not Bearer and the served enrolment token (%d characters received)", len(p.Authorization))
			}
			body := decodeAny(t, "the probe body", p.Body)
			failIf(t, !reflect.DeepEqual(body, map[string]any{"subscriptionId": fixtureSubID}), "the probe body = %v, want exactly {subscriptionId: %s}", body, fixtureSubID)
			keys := mapKeys(got)
			failIf(t, !slices.Equal(keys, []string{"checkedAt", "status"}) || got["status"] != float64(http.StatusConflict), "enrolmentReuse = %v, want exactly status 409 and checkedAt", got)
			assertUTCWithin(t, got["checkedAt"], start, end)
			keptPath := filepath.Join(r.dir, reuseResultFile)
			raw, err := os.ReadFile(keptPath)
			fatalIf(t, err != nil, "the probe kept no %s: %v", reuseResultFile, err)
			kept := decodeAny(t, reuseResultFile, raw)
			failIf(t, !reflect.DeepEqual(kept, any(got)), "%s = %v, want the reported enrolmentReuse %v", reuseResultFile, kept, got)
			info, err := os.Stat(keptPath)
			failIf(t, err != nil || info.Mode().Perm() != 0o600, "%s mode = %v (err %v), want 0600", reuseResultFile, info, err)
			r.send()
			n2 := len(r.probe.received())
			failIf(t, n2 != 1, "a second report probed again: %d probes in all, want one per node", n2)
			n3 := r.userData.hitCount(userDataPath)
			failIf(t, n3 != 1, "a second report read the user data again: %d reads in all, want one", n3)
			again := reuse(t, r)
			failIf(t, !reflect.DeepEqual(again, got), "the second report's enrolmentReuse = %v, want the kept %v", again, got)
		}},
	}
	for _, status := range []int{200, 204, 401, 403, 404, 409} {
		cases = append(cases, reportCase{name: "keeps the " + http.StatusText(status) + " answer to the probe and acts on none", opts: setup(fixtureEnrolmentToken, serving(fixtureEnrolmentToken), status), check: func(t *testing.T, r *reportRig) {
			got, _ := reuse(t, r)["status"].(float64)
			failIf(t, int(got) != status, "enrolmentReuse.status = %v, want %d", got, status)
			n := len(r.probe.received())
			failIf(t, n != 1, "the enrolment endpoint received %d probes, want exactly one", n)
			got2, err2 := os.ReadFile(filepath.Join(r.dir, enrolScriptJSONFile))
			failIf(t, err2 != nil || string(got2) != enrolledAnswer(t), "the probe changed %s (err2 %v)", enrolScriptJSONFile, err2)
			entries, err := os.ReadDir(r.dir)
			fatalIf(t, err != nil, "reading the enrolment directory: %v", err)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			want := []string{reuseResultFile, enrolScriptEnvFile, enrolScriptJSONFile}
			failIf(t, !slices.Equal(names, want), "the enrolment directory holds %v, want exactly %v", names, want)
			for _, sentinel := range []string{"enrol-sentinel-repository-read-key-0001", "enrol-sentinel-report-token-0001"} {
				failIf(t, strings.Contains(string(r.req.Body), sentinel) || strings.Contains(r.run.output(), sentinel), "the probe's answer reached the report or the script's output")
				assertNothingLeftHolding(t, "the report script", r.dir, []string{sentinel})
				assertNothingLeftHolding(t, "the report script", r.run.tmp, []string{sentinel})
			}
		}})
	}
	for _, tc := range []struct {
		name     string
		statuses []int
	}{{"endpoint unreachable", nil}, {"429 too many requests", []int{429}}, {"503 unavailable", []int{503}}} {
		name, statuses := tc.name, tc.statuses
		cases = append(cases, reportCase{name: "keeps nothing and probes again after " + name, opts: setup(fixtureEnrolmentToken, serving(fixtureEnrolmentToken), statuses...), manual: true, check: func(t *testing.T, r *reportRig) {
			for run := 1; run <= 2; run++ {
				r.send()
				got, ok := reportFields(t, r.req)["enrolmentReuse"]
				failIf(t, !ok || string(got) != "null", "report %d: enrolmentReuse = %s (present %v), want null after a probe that met no final answer", run, got, ok)
				_, err := os.Stat(filepath.Join(r.dir, reuseResultFile))
				failIf(t, err == nil, "report %d: the probe kept %s after %s", run, reuseResultFile, name)
				n := r.userData.hitCount(userDataPath)
				failIf(t, n != run, "report %d: the user data was read %d times in all, want %d: a probe that met no final answer runs again", run, n, run)
				if statuses != nil {
					n := len(r.probe.received())
					failIf(t, n != run, "report %d: the enrolment endpoint received %d probes in all, want %d", run, n, run)
				}
			}
		}})
	}
	for _, tc := range []struct {
		name     string
		userData reportOption
	}{
		{"metadata service answers 503", withUserData(http.StatusServiceUnavailable, "metadata service not ready")},
		{"user data without the token line", withUserData(http.StatusOK, "#cloud-config\nruncmd: []\n")},
		{"metadata service unreachable", withUnreachableUserData()},
	} {
		cases = append(cases, reportCase{name: "sends no probe when the " + tc.name, opts: setup(fixtureEnrolmentToken, tc.userData, http.StatusConflict), check: func(t *testing.T, r *reportRig) {
			n := len(r.probe.received())
			failIf(t, n != 0, "the probe sent %d requests with no served enrolment token, want none", n)
		}})
	}
	cases = append(cases, reportCase{name: "carries no node secret in the body, the probe, a command line or the kept result",
		opts: append(setup(fixtureEnrolmentToken, serving(fixtureEnrolmentToken), http.StatusConflict), recording(), withAnswer(tokenAnswer(t, fixtureRepositoryToken, fixtureReportToken)),
			withK3s(k3sServingSecret(fixtureRepositoryToken))),
		check: func(t *testing.T, r *reportRig) {
			k3sLines := strings.Join(r.k3s.calls(t), "\n")
			for _, read := range []string{"job", "helmchart", "app", "secret", argocdMetricsPath, kubeSystemMetricsPath, "plan", "system-upgrade", "kured"} {
				failIf(t, !strings.Contains(k3sLines, read), "k3s kubectl never read %s, so the checks below never saw the token it serves:\n%s", read, k3sLines)
			}
			probes := r.probe.received()
			fatalIf(t, len(probes) != 1, "the probe sent %d requests, want one, so the checks below would see no probe:\n%s", len(probes), r.run.output())
			for _, sent := range []struct {
				what string
				req  recordedEnrolRequest
			}{{"the probe", probes[0]}, {"the report", r.req}} {
				failIf(t, !sent.req.SawClient, "no process command line carried the endpoint URL while %s was open, so the scan saw nothing", sent.what)
				for _, line := range sent.req.TokenOnCmdline {
					t.Errorf("a process command line carried the token %s presents while it was open: %s", sent.what, line)
				}
			}
			lines := r.rec.commandLines(t)
			fatalIf(t, !strings.Contains(lines, "curl "), "the recorder saw no curl command line, so it saw nothing the script ran:\n%s", lines)
			kept, err := os.ReadFile(filepath.Join(r.dir, reuseResultFile))
			fatalIf(t, err != nil, "the probe kept no %s: %v", reuseResultFile, err)
			secrets := []struct {
				what      string
				fragments []string
			}{
				{"the enrolment token", []string{fixtureEnrolmentToken}},
				{"the report token", []string{fixtureReportToken}},
				{"the repository token", []string{fixtureRepositoryToken, base64.StdEncoding.EncodeToString([]byte(fixtureRepositoryToken))}},
			}
			places := []struct{ where, text string }{
				{"the report body", string(r.req.Body)}, {"the probe body", string(probes[0].Body)}, {"the script's output", r.run.output()},
				{"a command line the report script ran", lines}, {"a k3s kubectl command line", k3sLines}, {reuseResultFile, string(kept)},
			}
			for _, secret := range secrets {
				for _, place := range places {
					failIf(t, slices.ContainsFunc(secret.fragments, func(f string) bool { return strings.Contains(place.text, f) }), "%s carries %s", place.where, secret.what)
				}
				assertNothingLeftHolding(t, "the report script", r.run.tmp, secret.fragments)
			}
		}})
	runReportCases(t, cases)
}

func TestClosedAddr_RefusesConnectionsAndNoListenerCanTakeItWhileItsTestRuns(t *testing.T) {
	t.Parallel()
	addr := closedAddr(t)

	conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
	if dialErr == nil {
		_ = conn.Close()
	}
	l, listenErr := net.Listen("tcp", addr)
	if listenErr == nil {
		_ = l.Close()
	}

	failIf(t, !errors.Is(dialErr, syscall.ECONNREFUSED), "dialling the closed address %s error = %v; want connection refused", addr, dialErr)
	failIf(t, listenErr == nil, "net.Listen(%q) succeeded; want the closed address held while its test runs, so no parallel test's fake answers for it", addr)
}

func servedUserData(t *testing.T, token string) string {
	t.Helper()
	in := fixtureRenderInputs()
	in.EnrolmentToken = token
	ud := renderOK(t, in)
	return ud
}

func assertCertManagerRead(t *testing.T, calls []k3sCall, names []string) {
	t.Helper()
	reads := 0
	for _, c := range calls {
		if c.verb != "get" || len(c.resources()) != 1 || !slices.Contains(names, c.resources()[0]) {
			continue
		}
		reads++
		_, all := c.flags["-A"]
		_, allLong := c.flags["--all-namespaces"]
		failIf(t, !all && !allLong || c.flags["--output"] != "json" || c.flags["--request-timeout"] != "10s",
			"k3s kubectl read %s with %q, want -A -o json --request-timeout=10s", names[0], c.line())
	}
	failIf(t, reads != 1, "k3s kubectl read %s %d times, want once", names[0], reads)
}

func TestReportScript_ClusterFields(t *testing.T) {
	r := newReportRig(t).send()
	fields, calls := reportFields(t, r.req), k3sCallsOf(t, r.k3s)
	body, out := string(r.req.Body), r.run.output()
	noSecret := func(t *testing.T, what string, values ...string) {
		t.Helper()
		for _, v := range values {
			failIf(t, strings.Contains(body, v) || strings.Contains(out, v), "the report body or output carries %q, %s", v, what)
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(clusterSecretSentinel))
	checks := []struct {
		field string
		check func(t *testing.T)
	}{
		{"ciliumPods", func(t *testing.T) {
			if !slices.ContainsFunc(calls, func(c k3sCall) bool {
				return c.verb == "get" && c.flags["--namespace"] == "kube-system" && strings.Contains(c.line(), "pod") && strings.Contains(c.line(), "app.kubernetes.io/part-of=cilium")
			}) {
				t.Errorf("no k3s kubectl get of kube-system pods selected app.kubernetes.io/part-of=cilium; k3s ran with %q", r.k3s.calls(t))
			}
		}},
		{"helmInstallJobs", func(t *testing.T) {
			noSecret(t, "which no allowlisted field of a helm-install Job holds", clusterSecretSentinel, "chart-auth", ".svc,.cluster.local", "HELM_DRIVER", "traefik")
		}},
		{"helmCharts", func(t *testing.T) { noSecret(t, "a HelmChart's values or annotations", clusterSecretSentinel) }},
		{"applications", func(t *testing.T) {
			noSecret(t, "an Application's annotations", clusterSecretSentinel)
			for _, c := range calls {
				failIf(t, strings.Contains(c.line(), "application") && c.flags["--namespace"] != "argocd" && !strings.Contains(c.flags["--selector"], subscriptionLabel), "k3s kubectl read Applications with %q, want the argocd namespace", c.line())
			}
		}},
		{"repositorySecrets", func(t *testing.T) {
			reads := 0
			for _, c := range calls {
				if !strings.HasPrefix(c.line(), "kubectl ") || !strings.Contains(c.line(), "secret") {
					continue
				}
				reads++
				_, raw := c.flags["--raw"]
				_, sorted := c.flags["--sort-by"]
				failIf(t, c.verb != "get" || raw || sorted || !slices.Contains([]string{"", "wide", "name", "json"}, c.flags["--output"]), "k3s kubectl read Secrets other than with a get of kubectl's table, names or JSON: %q", c.line())
				if strings.Contains(c.flags["--selector"], subscriptionLabel) {
					continue
				}
				failIf(t, c.flags["--namespace"] != "argocd" || !strings.Contains(c.flags["--selector"], "argocd.argoproj.io/secret-type"), "k3s kubectl read Secrets outside the argocd namespace or without selecting argocd.argoproj.io/secret-type: %q", c.line())
			}
			failIf(t, reads == 0, "k3s kubectl never read the argocd Secrets; it ran with %q", r.k3s.calls(t))
			noSecret(t, "a Secret's data, annotation or unlabelled name", clusterSecretSentinel, encoded, "eC1hY2Nlc3MtdG9rZW4=", "aHR0cHM6Ly9naXRodWIuY29t", "argocd-secret")
			archive, err := os.ReadFile(r.run.hostTar)
			fatalIf(t, err != nil, "reading host.tar: %v", err)
			for _, v := range []string{clusterSecretSentinel, encoded} {
				failIf(t, strings.Contains(string(archive), v), "host.tar carries %q, so a Secret's data reaches the report container", v)
			}
		}},
		{"appProjects", func(t *testing.T) {
			noSecret(t, "an AppProject's annotations", clusterSecretSentinel)
			reads := 0
			for _, c := range calls {
				if c.verb == "get" && slices.ContainsFunc(c.resources(), func(w string) bool { return strings.HasPrefix(w, "appproject") }) && !strings.Contains(c.flags["--selector"], subscriptionLabel) {
					reads++
					failIf(t, c.flags["--namespace"] != "argocd" || c.flags["--output"] != "json", "k3s kubectl read the AppProjects with %q, want -n argocd -o json", c.line())
				}
			}
			failIf(t, reads != 1, "k3s kubectl read the argocd AppProjects %d times, want once", reads)
		}},
		{"podMemory", func(t *testing.T) {
			for _, path := range []string{argocdMetricsPath, kubeSystemMetricsPath} {
				failIf(t, !slices.ContainsFunc(calls, func(c k3sCall) bool { return strings.Contains(c.flags["--raw"], path) }), "k3s kubectl never read %s with get --raw", path)
			}
		}},
		{"podSecurity", func(t *testing.T) {
			noSecret(t, "a namespace's annotation", clusterSecretSentinel)
			reads := 0
			for _, c := range calls {
				if words := c.resources(); c.verb == "get" && len(words) == 1 && slices.Contains([]string{"namespaces", "namespace", "ns"}, words[0]) && !strings.Contains(c.flags["--selector"], subscriptionLabel) {
					reads++
					failIf(t, c.flags["--output"] != "json", "k3s kubectl read the namespaces for podSecurity with %q, want -o json", c.line())
				}
			}
			failIf(t, reads != 1, "k3s kubectl read the namespaces for podSecurity %d times, want once", reads)
		}},
		{"subscriptionResources", func(t *testing.T) {
			secretReadCount := 0
			for _, c := range calls {
				raw, ok := c.flags["--raw"]
				failIf(t, ok && strings.Contains(raw, "secrets"), "k3s kubectl read Secrets with --raw, which fetches their data: %q", c.line())
				if !strings.Contains(c.flags["--selector"], subscriptionLabel) || !slices.ContainsFunc(c.resources(), func(w string) bool { return w == "secret" || w == "secrets" }) {
					continue
				}
				secretReadCount++
				_, sorted := c.flags["--sort-by"]
				_, templated := c.flags["--template"]
				failIf(t, c.verb != "get" || sorted || templated || !slices.Contains([]string{"", "wide", "name"}, c.flags["--output"]), "k3s kubectl read Secrets other than with a get of kubectl's table or names: %q", c.line())
			}
			failIf(t, secretReadCount == 0, "no k3s kubectl get selecting %s named Secrets", subscriptionLabel)
			noSecret(t, "a Secret's data or annotation", clusterSecretSentinel, encoded)
		}},
		{"jwks", func(t *testing.T) {
			got := fields["jwks"]
			fatalIf(t, len(got) == 0 || got[0] != '{', "jwks = %s, want the key set as a JSON object", truncate(string(got), 200))
			reads := 0
			for _, c := range calls {
				if c.verb == "get" && c.flags["--raw"] == jwksPath {
					reads++
					got := c.flags["--request-timeout"]
					failIf(t, got != "10s", "k3s kubectl read the key set with --request-timeout %q, want 10s: %q", got, c.argv)
				}
			}
			failIf(t, reads != 1, "k3s kubectl read get --raw %s %d times, want once", jwksPath, reads)
		}},
		{"admission", func(t *testing.T) {
			reads, applies := 0, 0
			for _, c := range calls {
				switch {
				case c.verb == "get" && c.names("admission-fixtures", "configmap", "configmaps", "cm"):
					reads++
					failIf(t, !slices.Contains([]string{admissionNamespace, "mitstack-node"}, c.flags["--namespace"]) || c.flags["--output"] != "json" || c.flags["--request-timeout"] != "10s", "k3s kubectl read the fixtures with %q, want the ConfigMap admission-fixtures in %s or mitstack-node as JSON with --request-timeout=10s", c.line(), admissionNamespace)
				case c.verb == "apply":
					applies++
					failIf(t, c.flags["--dry-run"] != "server" || c.flags["--namespace"] != admissionNamespace || c.flags["--filename"] != "-" || c.flags["--request-timeout"] != "10s",
						"k3s kubectl applied with %q, want --dry-run=server -n %s -f - and --request-timeout=10s", c.line(), admissionNamespace)
				}
			}
			failIf(t, reads != 2, "k3s kubectl read an admission-fixtures ConfigMap %d times, want once in each namespace", reads)
			failIf(t, applies != 6, "k3s kubectl applied %d fixtures, want one per rule, 6", applies)
		}},
		{"defaultDenyPolicies", func(t *testing.T) {
			reads := 0
			for _, c := range calls {
				if c.verb != "get" || len(c.resources()) != 1 || !slices.Contains([]string{"networkpolicies", "networkpolicy", "netpol"}, c.resources()[0]) {
					continue
				}
				reads++
				_, all := c.flags["-A"]
				_, allLong := c.flags["--all-namespaces"]
				failIf(t, !all && !allLong || c.flags["--field-selector"] != "metadata.name=mitstack-default-deny" || c.flags["--output"] != "json" || c.flags["--request-timeout"] != "10s",
					"k3s kubectl read NetworkPolicies with %q, want -A --field-selector metadata.name=mitstack-default-deny -o json --request-timeout=10s", c.line())
			}
			failIf(t, reads != 1, "k3s kubectl read the generated NetworkPolicies %d times, want once", reads)
		}},
		{"certificates", func(t *testing.T) {
			assertCertManagerRead(t, calls, []string{"certificates", "certificate", "cert", "certificates.cert-manager.io"})
		}},
		{"challenges", func(t *testing.T) {
			assertCertManagerRead(t, calls, []string{"challenges", "challenge", "challenges.acme.cert-manager.io"})
		}},
		{"cloudNativePG", func(t *testing.T) {
			want := []string{"clusters.postgresql.cnpg.io", "databases.postgresql.cnpg.io", "databaseroles.postgresql.cnpg.io"}
			reads := 0
			for _, c := range calls {
				if c.verb != "get" || !slices.ContainsFunc(c.resources(), func(w string) bool { return strings.Contains(w, "cnpg.io") }) {
					continue
				}
				reads++
				_, all := c.flags["-A"]
				failIf(t, !slices.Equal(c.resources(), want) || !all || c.flags["--output"] != "json" || c.flags["--request-timeout"] != "10s",
					"k3s kubectl read CloudNativePG with %q, want get %s -A -o json --request-timeout=10s", c.line(), strings.Join(want, ","))
			}
			failIf(t, reads != 1, "k3s kubectl read CloudNativePG's objects %d times, want once, in a read of its own", reads)
		}},
	}
	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			assertClusterField(t, c.field, fields[c.field])
			c.check(t)
		})
	}
	t.Run("podSecurityDryRun", func(t *testing.T) {
		assertDryRunAnswered(t, fields["podSecurityDryRun"])
		labels := 0
		for _, c := range calls {
			switch {
			case c.line() == "secrets-encrypt status":
			case c.verb == "exec":
				failIf(t, c.flags["--namespace"] != "kube-system" || !slices.Contains([]string{ciliumStatusCommand, hubbleObserveCommand}, strings.Join(c.command, " ")), "k3s kubectl ran %q; the report execs only %s and %s in kube-system", c.line(), ciliumStatusCommand, hubbleObserveCommand)
			case c.verb == "logs" && c.flags["--namespace"] == "kube-system":
				failIf(t, !c.names("kured", "ds", "daemonset", "daemonsets"), "k3s kubectl ran %q; in kube-system the report reads only the log of ds/kured", c.line())
			case slices.Contains([]string{"create", "run", "wait", "logs", "delete"}, c.verb):
				failIf(t, !strings.Contains(c.line(), metadataProbeNamespace), "k3s kubectl ran %q outside the metadata probe's namespace %s", c.line(), metadataProbeNamespace)
			case c.verb == "get":
			case c.verb == "apply":
				failIf(t, c.flags["--dry-run"] != "server", "k3s kubectl ran %q; the report applies only as --dry-run=server, which persists nothing", c.line())
			case c.verb == "label":
				labels++
				_, overwrite := c.flags["--overwrite"]
				if c.flags["--dry-run"] != "server" || !overwrite || !slices.Contains(c.argv, "pod-security.kubernetes.io/enforce=restricted") ||
					!regexp.MustCompile(`\b(namespaces?|ns|namespace/)\s*argocd\b`).MatchString(c.line()) {
					t.Errorf("the dry run must label the argocd namespace pod-security.kubernetes.io/enforce=restricted with --overwrite and --dry-run=server: %q", c.line())
				}
			default:
				t.Errorf("k3s kubectl ran %q; the report only reads, dry-runs and probes the metadata service in its own namespace", c.line())
			}
		}
		failIf(t, labels != 1, "k3s kubectl labelled %d times, want the one dry run", labels)
	})
}

func cannedNamespace(name, phase string, labels, annotations map[string]any) map[string]any {
	all := map[string]any{"kubernetes.io/metadata.name": name}
	maps.Copy(all, labels)
	meta := map[string]any{"name": name, "labels": all, "creationTimestamp": "2026-10-01T09:16:02Z"}
	if annotations != nil {
		meta["annotations"] = annotations
	}
	return map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": meta, "spec": map[string]any{"finalizers": []any{"kubernetes"}}, "status": map[string]any{"phase": phase}}
}

func certificateIn(namespace, name, status, reason, message string) map[string]any {
	return map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{"name": name, "namespace": namespace},
		"status":   map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": status, "reason": reason, "message": message}}},
	}
}

func extremeList(items []any) string {
	return mustJSON(map[string]any{"apiVersion": "v1", "kind": "List", "metadata": map[string]any{"resourceVersion": ""}, "items": items})
}

func jwksOfLength(size int) string {
	const head, tail, sep = `{"keys": [`, `]}`, ", "
	key := func(i int, n string) string {
		return fmt.Sprintf(`{"use": "sig", "kty": "RSA", "kid": "key-%05d", "alg": "RS256", "n": "%s", "e": "AQAB"}`, i, n)
	}
	modulus := func(n int) string { return strings.Repeat("x7Q-", n/4+1)[:n] }
	full := key(0, modulus(342))
	var keys []string
	used := len(head) + len(tail)
	for used+len(full)+len(sep)+len(key(len(keys)+1, "")) <= size {
		keys = append(keys, key(len(keys), modulus(342)))
		used += len(full) + len(sep)
	}
	pad := size - used - len(key(len(keys), ""))
	keys = append(keys, key(len(keys), modulus(pad)))
	doc := head + strings.Join(keys, sep) + tail
	if pad < 0 || len(doc) != size || !json.Valid([]byte(doc)) {
		panic(fmt.Sprintf("jwksOfLength made %d bytes, want %d", len(doc), size))
	}
	return doc
}

func labelledConfigMapRows(n int) (string, []any) {
	var table strings.Builder
	entries := make([]any, 0, n)
	for i := range n {
		prefix := fmt.Sprintf("budget-%03d-", i)
		entry := fmt.Sprintf(`{"namespace": %q, "kind": %q, "name": %q, "subscription": %q}`, "demo", "configmap", prefix, demoSubscription)
		name := prefix + strings.Repeat("x", labelledRowCost-2-len(entry))
		fmt.Fprintf(&table, "demo   configmap/%s   1   5d   %s\n", name, demoSubscription)
		entries = append(entries, map[string]any{"namespace": "demo", "kind": "configmap", "name": name, "subscription": demoSubscription})
	}
	return table.String(), entries
}

func extremeClusterAnswers() []fakeK3sOption {
	argocd, cilium := map[string]any{"app.kubernetes.io/part-of": "argocd"}, map[string]any{"app.kubernetes.io/part-of": "cilium"}
	return []fakeK3sOption{
		k3sGenerate(readArgoCDPods, "pods", 2000, "argocd-pod", argocd), k3sGenerate(readKubeSystem, "pods", 2000, "cilium-pod", cilium),
		k3sGenerate(readJobs, "helmJobs", 2000, "", nil), k3sGenerate(readHelmCharts, "helmCharts", 2000, "", nil),
		k3sGenerate(readApplications, "applications", 300, "", nil), k3sGenerate(readSecrets, "repositorySecrets", 2000, "", nil),
		k3sGenerate(readArgoCDMetrics, "metrics", 2000, "argocd-pod", argocd), k3sGenerate(readCiliumMetrics, "metrics", 2000, "cilium-pod", cilium),
		k3sLabel(testFile("report/dry-run-stdout.txt"), strings.Repeat("Warning: "+strings.Repeat("w", 100)+"\n", 10000), 0),
		k3sGenerate(readNamespaces, "namespaces", 3000, "", nil), k3sGenerate(readSubscriptionResources, "subscriptionObjects", 3000, "", nil),
		k3sPrinting(readJWKS, jwksOfLength(jwksLimit)),
		k3sGenerate(readDefaultDeny, "networkPolicies", 3000, "", nil), k3sGenerate(readAdmissionFixtures, "admissionFixtures", 40, "", nil),
		k3sGenerate(readCloudNativePG, "cloudNativePGObjects", 3000, "", nil),
	}
}

func extremePatchingAnswers() []fakeK3sOption {
	return []fakeK3sOption{k3sLogs(readKuredLog, largestToolOutput), k3sLogs(readKuredPreviousLog, largestToolOutput),
		k3sGenerate(readUpgradePlans, "plans", 300, "", nil), k3sGenerate(readUpgradeJobs, "upgradeJobs", 2000, "", nil)}
}

func largestLogs() (journal, cloudInit []string) {
	journal, cloudInit = make([]string, 600), make([]string, 1000)
	for i := range journal {
		journal[i] = fmt.Sprintf("2026-10-01T09:00:00.000000+00:00 orbitdemo-abcd2345 k3s[900]: %04d %s", i+1, strings.Repeat("j", 950))
	}
	for i := range cloudInit {
		cloudInit[i] = fmt.Sprintf("cloud-init %04d %s", i+1, strings.Repeat("c", 980))
	}
	return journal, cloudInit
}

func largestUnattendedUpgradesLog() []string {
	lines := make([]string, 2000)
	for i := range lines {
		lines[i] = fmt.Sprintf("2026-10-07 01:30:%02d,%03d INFO line %04d %s", i%60, i%1000, i+1, strings.Repeat("u", 160))
	}
	return lines
}

func largestNonASCIICheck(t *testing.T) string {
	t.Helper()
	var check map[string]any
	err := json.Unmarshal([]byte(testFile("report/patch-check.json")), &check)
	fatalIf(t, err != nil, "the canned patch check: %v", err)
	osPart := check["os"].(map[string]any)
	for n := 1; ; n++ {
		osPart["running"] = strings.Repeat("é", n)
		if len(mustJSON(check)) > patchCheckFileLimit-2 {
			osPart["running"] = strings.Repeat("é", n-1)
			return mustJSON(check)
		}
	}
}

func kuredDrainLog(draining, commanding string) string {
	var b strings.Builder
	for i := range 12 {
		fmt.Fprintf(&b, "time=\"2026-10-08T01:%02d:41Z\" level=info msg=\"Reboot not required\" node=orbitdemo-abcd2345 sentinel=/var/run/reboot-required\n", i*5)
	}
	b.WriteString(`time="2026-10-08T02:00:41Z" level=info msg="Reboot required"` + "\n" + `time="2026-10-08T02:00:41Z" level=info msg="Acquired reboot lock"` + "\n" + draining + "\n")
	for i := range 12 {
		fmt.Fprintf(&b, "time=\"2026-10-08T02:00:%02dZ\" level=info msg=\"evicting pod argocd/argocd-application-controller-%02d-7c9d8f6b5d-4kq2m\" node=orbitdemo-abcd2345 namespace=argocd pod=argocd-application-controller-%02d-7c9d8f6b5d-4kq2m\n", 42+i, i, i)
	}
	return b.String() + commanding + "\n"
}

func TestReportScript_AClusterWithoutCloudNativePGsCRDsStillFilesEveryOtherRead(t *testing.T) {
	const missing = `error: the server doesn't have a resource type "clusters"`
	r := newReportRig(t, withK3s(k3sFailing(readCloudNativePG, 1, missing+"\n"))).send()
	fields := reportFields(t, r.req)
	read := clusterRead{readCloudNativePG, "cloudNativePG", ""}

	assertKubectlFailure(t, read.name(), read.in(t, fields), 1, missing)
	assertClusterAnsweredBut(t, fields, read)
}

func TestReportScript_ClusterReadsFailIndependently(t *testing.T) {
	const forbidden = `Error from server (Forbidden): configmaps is forbidden: User "system:admin" cannot list resource "configmaps" in API group "" at the cluster scope`
	reads := append(slices.Clone(clusterReads), clusterRead{readNodes, "kubernetes", ""}, clusterRead{readLabel, "podSecurityDryRun", ""})
	var cases []reportCase
	for _, rd := range reads {
		message := "Error from server (ServiceUnavailable): the server is currently unable to handle the request (" + rd.read + ")"
		cases = append(cases, reportCase{name: "a failed " + rd.name() + " read records its failure and every other field reports", opts: []reportOption{withK3s(k3sFailing(rd.read, 1, message+"\n"))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			if rd.field == "podSecurityDryRun" {
				status, output := dryRunResult(t, fields[rd.field])
				failIf(t, status != 1 || !strings.Contains(output, message), "podSecurityDryRun = %s, want exitStatus 1 and the failed dry run's stderr", fields[rd.field])
			} else {
				assertKubectlFailure(t, rd.name(), rd.in(t, fields), 1, message)
			}
			assertClusterAnsweredBut(t, fields, rd)
		}})
		if rd.read == readSecrets || rd.read == readSubscriptionResources || rd.field == "kubernetes" || rd.field == "podSecurityDryRun" {
			continue
		}
		cases = append(cases, reportCase{name: "a " + rd.name() + " read that is not JSON records why and every other field reports", opts: []reportOption{withK3s(k3sPrinting(rd.read, "NAME            READY   STATUS\nsomething-else  1/1     Running\n"))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			assertKubectlFailure(t, rd.name(), rd.in(t, fields), 0, "")
			assertClusterAnsweredBut(t, fields, rd)
		}})
	}
	sub := clusterRead{readSubscriptionResources, "subscriptionResources", ""}
	for _, tc := range []struct{ name, stdout string }{
		{"a single column", "orbitdemo\n"},
		{"no kind/name column", "orbitdemo   configmap   " + fixtureSubID + "\n"},
		{"a good row then a stray", "orbitdemo   configmap/orbitdemo-config   " + fixtureSubID + "\nstray\n"},
	} {
		cases = append(cases, reportCase{name: "a labelled objects row out of shape (" + tc.name + ") records why and every other field reports", opts: []reportOption{withK3s(k3sPrinting(sub.read, tc.stdout))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			assertKubectlFailure(t, sub.field, fields[sub.field], 0, "labelled objects table")
			assertClusterAnsweredBut(t, fields, sub)
		}})
	}
	filling := subscriptionResourcesLimit / labelledRowCost
	fillingTable, fillingEntries := labelledConfigMapRows(filling)
	pastTable, pastEntries := labelledConfigMapRows(filling + 1)
	unlabelled := extremeList([]any{cannedNamespace("default", "Active", nil, nil), cannedNamespace("kube-system", "Active", nil, nil), cannedNamespace("argocd", "Active", nil, nil)})
	assertEntries := func(want []any) func(t *testing.T, got []byte) {
		return func(t *testing.T, got []byte) {
			var entries []any
			err := json.Unmarshal(got, &entries)
			failIf(t, err != nil || entries == nil || !reflect.DeepEqual(entries, want), "subscriptionResources = %s (err %v), want the first %d rows of the table in order", truncate(string(got), 300), err, len(want))
		}
	}
	for _, c := range []struct {
		name     string
		opts     []fakeK3sOption
		complete bool
		check    func(t *testing.T, got []byte)
	}{
		{"a table within the budget", nil, true, func(t *testing.T, got []byte) { assertClusterField(t, "subscriptionResources", got) }},
		{"a table filling the budget exactly", []fakeK3sOption{k3sPrinting(readSubscriptionResources, fillingTable)}, true, assertEntries(fillingEntries)},
		{"a table one row past the budget", []fakeK3sOption{k3sPrinting(readSubscriptionResources, pastTable)}, false, assertEntries(pastEntries[:filling])},
		{"no labelled object at all", []fakeK3sOption{k3sAnswer(readSubscriptionResources, extremeList([]any{})), k3sAnswer(readNamespaces, unlabelled)}, true, assertEntries([]any{})},
		{"a failed read", []fakeK3sOption{k3sFailing(readSubscriptionResources, 1, forbidden+"\n")}, false, func(t *testing.T, got []byte) { assertKubectlFailure(t, "subscriptionResources", got, 1, forbidden) }},
		{"a read that exits 0 printing something other than the table", []fakeK3sOption{k3sPrinting(readSubscriptionResources, "orbitdemo\n")}, false, func(t *testing.T, got []byte) {
			assertKubectlFailure(t, "subscriptionResources", got, 0, "labelled objects table")
		}},
	} {
		cases = append(cases, reportCase{name: "subscriptionResourcesComplete is " + strconv.FormatBool(c.complete) + " for " + c.name, opts: []reportOption{withK3s(c.opts...)}, manual: true, check: func(t *testing.T, r *reportRig) {
			start := time.Now()
			fields := r.send().fields()
			assertMadeAt(t, fields, start, time.Now())
			c.check(t, fields["subscriptionResources"])
			var complete bool
			err := json.Unmarshal(fields["subscriptionResourcesComplete"], &complete)
			failIf(t, err != nil || complete != c.complete, "subscriptionResourcesComplete = %s (err %v), want %v", fields["subscriptionResourcesComplete"], err, c.complete)
		}})
	}
	unread := mustJSON(map[string]any{"exitStatus": 0, "stderr": jwksUnreadable})
	for _, tc := range []struct{ name, stdout, want string }{
		{"a key set of exactly the bound", jwksOfLength(jwksLimit), jwksOfLength(jwksLimit)},
		{"a key set a byte past it", jwksOfLength(jwksLimit + 1), unread},
		{"a megabyte of keys", jwksOfLength(1 << 20), unread},
		{"text", "404 page not found\n", unread},
		{"nothing", "", unread},
	} {
		jwks := clusterRead{readJWKS, "jwks", ""}
		cases = append(cases, reportCase{name: "jwks carries " + tc.name + " as the bound says", opts: []reportOption{withK3s(k3sPrinting(jwks.read, tc.stdout))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			sameJSON(t, "jwks", fields["jwks"], tc.want)
			assertClusterAnsweredBut(t, fields, jwks)
		}})
	}
	cases = append(cases, reportCase{name: "podSecurity and subscriptionResources keep whole entries within their bounds", opts: []reportOption{withK3s(k3sGenerate(readNamespaces, "namespaces", 3000, "", nil), k3sGenerate(readSubscriptionResources, "subscriptionObjects", 3000, "", nil))}, check: func(t *testing.T, r *reportRig) {
		fields := reportFields(t, r.req)
		for _, b := range []struct {
			field string
			limit int
			keys  []string
		}{{"podSecurity", podSecurityLimit, []string{"enforce", "name"}}, {"subscriptionResources", subscriptionResourcesLimit, []string{"kind", "name", "namespace", "subscription"}}} {
			assertNonEmptyList(t, b.field, fields[b.field])
			n := len(fields[b.field])
			failIf(t, n > b.limit, "%s is %d bytes of JSON text, want whole entries within %d", b.field, n, b.limit)
			var entries []map[string]json.RawMessage
			err := json.Unmarshal(fields[b.field], &entries)
			fatalIf(t, err != nil, "%s = %s, want a list of objects", b.field, truncate(string(fields[b.field]), 200))
			for i, e := range entries {
				if keys := mapKeys(e); !slices.Equal(keys, b.keys) {
					t.Errorf("%s[%d] has keys %v, want exactly %v", b.field, i, keys, b.keys)
					break
				}
			}
		}
		failIf(t, strings.Contains(string(r.req.Body), base64.StdEncoding.EncodeToString([]byte(clusterSecretSentinel))), "the report body carries a Secret's data")
	}})
	before, after := "text-before-the-nul", "text-after-the-nul"
	for _, tc := range []struct {
		name, stdout, stderr string
		exit                 int
		contains             []string
	}{
		{"a megabyte of warnings", testFile("report/dry-run-stdout.txt"), strings.Repeat("Warning: W\n", 100000), 0, []string{"Warning: W"}},
		{"a NUL in the warnings", testFile("report/dry-run-stdout.txt"), "Warning: " + before + "\x00" + after + "\n", 0, []string{before, after}},
		{"the namespace is gone", "", "Error from server (NotFound): namespaces \"argocd\" not found\n", 1, []string{`namespaces "argocd" not found`}},
	} {
		cases = append(cases, reportCase{name: "the dry run output is bounded and carries no NUL: " + tc.name, opts: []reportOption{withK3s(k3sLabel(tc.stdout, tc.stderr, tc.exit))}, check: func(t *testing.T, r *reportRig) {
			assertNoNUL(t, "the dry run's output", r.req.Body)
			status, output := dryRunResult(t, reportFields(t, r.req)["podSecurityDryRun"])
			failIf(t, status != tc.exit, "podSecurityDryRun.exitStatus = %d, want %d", status, tc.exit)
			for _, want := range tc.contains {
				failIf(t, !strings.Contains(output, want), "podSecurityDryRun.output = %q, want it to carry %q", truncate(output, 200), want)
			}
		}})
	}
	runReportCases(t, cases)
}

func TestReportScript_Hardening(t *testing.T) {
	const before, after = "text-before-the-nul", "text-after-the-nul"
	failures := []struct {
		field   string
		opts    []reportOption
		exit    int // -1 is any non-zero status
		message string
	}{
		{"secretsEncryption", []reportOption{withK3s(k3sSecretsEncrypt("", "time=\"2026-10-04T09:50:00Z\" level=fatal msg=\"secrets-encrypt status: Unauthorized\"\n", 1))}, 1, "secrets-encrypt status: Unauthorized"},
		{"ciliumStatus", []reportOption{withK3s(k3sExec(ciliumStatusCommand, "", "error: unable to upgrade connection: container not found (\"cilium-agent\")\n", 1))}, 1, `container not found ("cilium-agent")`},
		{"hubbleObserve", []reportOption{withK3s(k3sExec(hubbleObserveCommand, "", "failed to connect to 'unix:///var/run/cilium/hubble.sock': connection error\n", 2))}, 2, "failed to connect to 'unix:///var/run/cilium/hubble.sock'"},
		{"listeners", []reportOption{withTool(reportSSEnv, "ss", "", "Cannot open netlink socket: Operation not permitted\n", 1)}, 1, "Cannot open netlink socket"},
		{"sshUnits", []reportOption{withMissingTool(reportSystemctlEnv)}, -1, ""},
		{"metadataGuard", []reportOption{withTool(reportNftEnv, "nft", "", "Error: No such file or directory\nlist table inet mitstack_metadata_guard\n                 ^^^^^^^^^^^^^^^^^^^^^^^\n", 1)}, 1, "Error: No such file or directory"},
		{"kubelet", []reportOption{withK3s(k3sFailing(readConfigz, 1, "Error from server (ServiceUnavailable): the server is currently unable to handle the request\n"))}, 1, "the server is currently unable to handle the request"},
	}
	cases := []reportCase{
		{name: "runs ss, systemctl and nft from PATH when no override is set", opts: []reportOption{withToolsFromPATH()}, check: func(t *testing.T, r *reportRig) {
			h := hardeningOf(t, reportFields(t, r.req))
			for _, tool := range []struct {
				name string
				c    hardeningCommand
			}{{"ss", hardeningCommands[3]}, {"systemctl", hardeningCommands[4]}, {"nft", hardeningCommands[5]}} {
				failIf(t, len(r.tools[tool.name].runs(t)) == 0, "with its override unset the report never ran %s from PATH", tool.name)
				assertCommandAnswered(t, tool.c, h)
			}
		}},
		{name: "secretsEncryption carries stdout and stderr together", opts: []reportOption{withK3s(k3sSecretsEncrypt("Encryption Status: Enabled\n", "time=\"2026-10-04T09:50:00Z\" level=warning msg=\"the server token file is world readable\"\n", 0))}, check: func(t *testing.T, r *reportRig) {
			_, output := commandResult(t, "hardening.secretsEncryption", hardeningOf(t, reportFields(t, r.req))["secretsEncryption"], secretsEncryptionLimit)
			assertNamesAll(t, "hardening.secretsEncryption.output", output, "Encryption Status: Enabled", `level=warning msg="the server token file is world readable"`)
		}},
		{name: "carries each control's evidence as the command is run", opts: []reportOption{withTool(reportSSEnv, "ss", testFile("report/listeners.txt"), "", 0),
			withTool(reportSystemctlEnv, "systemctl", cannedSSHUnits, "", 1), withTool(reportNftEnv, "nft", testFile("report/metadata-guard.txt"), "", 0)}, check: func(t *testing.T, r *reportRig) {
			h, calls := hardeningOf(t, reportFields(t, r.req)), k3sCallsOf(t, r.k3s)
			execRan := func(command string) bool {
				return slices.ContainsFunc(calls, func(c k3sCall) bool {
					return c.verb == "exec" && c.names("cilium", "ds", "daemonset", "daemonsets") && c.flags["--namespace"] == "kube-system" &&
						c.flags["--container"] == "cilium-agent" && strings.Join(c.command, " ") == command
				})
			}
			ran := map[string][]string{"listeners": {"ss", "-tlnp"}, "sshUnits": {"systemctl", "is-enabled", "ssh.service", "ssh.socket"}, "metadataGuard": {"nft", "list", "table", "inet", metadataGuardTable}}
			for _, c := range hardeningCommands {
				assertCommandAnswered(t, c, h)
				switch want := ran[c.field]; {
				case c.field == "secretsEncryption":
					failIf(t, !slices.ContainsFunc(r.k3s.argvs(t), func(a []string) bool { return slices.Equal(a, []string{"secrets-encrypt", "status"}) }), "k3s never ran secrets-encrypt status; it ran with %q", r.k3s.calls(t))
				case c.field == "ciliumStatus" && !execRan(ciliumStatusCommand), c.field == "hubbleObserve" && !execRan(hubbleObserveCommand):
					t.Errorf("k3s kubectl never ran %s in the cilium-agent container of ds/cilium in kube-system", c.field)
				case want != nil && !r.tools[want[0]].ran(t, want[1:]...):
					t.Errorf("%s ran with %q, want a run with %q", want[0], r.tools[want[0]].runs(t), want[1:])
				}
			}
			got := string(h["metadataProbe"])
			failIf(t, got != "null", "hardening.metadataProbe = %s, want null while no probe has kept a result", truncate(got, 200))
		}},
	}
	for _, f := range failures {
		cases = append(cases, reportCase{name: "a failed " + f.field + " records its own failure and every other field reports", opts: f.opts, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			h := hardeningOf(t, fields)
			for _, c := range hardeningCommands {
				if c.field != f.field {
					assertCommandAnswered(t, c, h)
					continue
				}
				status, output := commandResult(t, "hardening."+c.field, h[c.field], c.limit)
				failIf(t, (f.exit < 0 && status <= 0) || (f.exit >= 0 && status != f.exit) || !strings.Contains(output, f.message), "hardening.%s = exitStatus %d, output %q, want the failed command's status (%d, or any non-zero for -1) and output carrying %q", c.field, status, truncate(output, 300), f.exit, f.message)
			}
			if f.field == "kubelet" {
				assertKubectlFailure(t, "hardening.kubelet", h["kubelet"], f.exit, f.message)
			} else {
				sameJSON(t, "hardening.kubelet", h["kubelet"], testFile("want/kubelet.json"))
			}
			assertClusterAnsweredBut(t, fields, clusterRead{})
		}})
	}
	for _, tc := range []struct {
		name, stdout string
		contains     []string
	}{
		{"far past each limit", largestToolOutput, nil},
		{"a NUL in each output", before + "\x00" + after + "\n", []string{before, after}},
	} {
		stdout, contains := tc.stdout, tc.contains
		cases = append(cases, reportCase{name: "outputs are bounded and carry no NUL: " + tc.name,
			opts: []reportOption{withK3s(k3sSecretsEncrypt(stdout, "", 0), k3sExec(ciliumStatusCommand, stdout, "", 0), k3sExec(hubbleObserveCommand, stdout, "", 0)),
				withTool(reportSSEnv, "ss", stdout, "", 0), withTool(reportSystemctlEnv, "systemctl", stdout, "", 0), withTool(reportNftEnv, "nft", stdout, "", 0)},
			check: func(t *testing.T, r *reportRig) {
				assertNoNUL(t, "a hardening command's output", r.req.Body)
				fields := reportFields(t, r.req)
				type namedOutput struct{ what, output string }
				var outputs []namedOutput
				for _, c := range hardeningCommands {
					_, output := commandResult(t, "hardening."+c.field, hardeningOf(t, fields)[c.field], c.limit)
					outputs = append(outputs, namedOutput{"hardening." + c.field, output})
				}
				_, units := commandResult(t, "patching.autoUpgradeUnits", patchingOf(t, fields)["autoUpgradeUnits"], autoUpgradeUnitsLimit)
				outputs = append(outputs, namedOutput{"patching.autoUpgradeUnits", units})
				for _, o := range outputs {
					failIf(t, o.output == "", "%s.output is empty, want what the command printed, bounded", o.what)
					assertNamesAll(t, o.what+".output", o.output, contains...)
				}
			}})
	}
	const refused = "Error from server (ServiceUnavailable): the server is currently unable to handle the request (get nodes)"
	cases = append(cases, reportCase{name: "kubelet carries eviction and reservations from the live config of this node", check: func(t *testing.T, r *reportRig) {
		sameJSON(t, "hardening.kubelet", hardeningOf(t, reportFields(t, r.req))["kubelet"], testFile("want/kubelet.json"))
		want := "/api/v1/nodes/" + hostNodeName(t) + "/proxy/configz"
		failIf(t, !slices.ContainsFunc(k3sCallsOf(t, r.k3s), func(c k3sCall) bool { return c.verb == "get" && c.flags["--raw"] == want }), "k3s kubectl never read get --raw %s; it ran with %q", want, r.k3s.calls(t))
	}})
	for _, tc := range []struct {
		name    string
		opt     fakeK3sOption
		exit    int
		message string
	}{
		{"the read fails", k3sFailing(readConfigz, 1, refused+"\n"), 1, refused},
		{"the answer is text", k3sPrinting(readConfigz, "404 page not found\n"), 0, ""},
		{"no kubeletconfig in it", k3sConfigz(`{"apiVersion": "v1", "kind": "Status"}`), 0, ""},
	} {
		cases = append(cases, reportCase{name: "kubelet records a configz read it cannot use and still reports: " + tc.name, opts: []reportOption{withK3s(tc.opt)}, check: func(t *testing.T, r *reportRig) {
			assertKubectlFailure(t, "hardening.kubelet", hardeningOf(t, reportFields(t, r.req))["kubelet"], tc.exit, tc.message)
		}})
	}
	runReportCases(t, cases)
}

type keptProbe struct {
	CheckedAt          string `json:"checkedAt"`
	PodCreatedAt       string `json:"podCreatedAt"`
	ContainerStartedAt string `json:"containerStartedAt"`
	Log                string `json:"log"`
}

func decodeKeptProbe(t *testing.T, what string, raw []byte) keptProbe {
	t.Helper()
	objectOf(t, what, raw, "checkedAt", "containerStartedAt", "log", "podCreatedAt")
	var p keptProbe
	err := json.Unmarshal(raw, &p)
	failIf(t, err != nil, "%s = %s, want four strings (%v)", what, truncate(string(raw), 300), err)
	return p
}

// withLargestProbe has the probe Job's pod log as much as the report carries.
func withLargestProbe() reportOption {
	return withK3s(k3sMetadataProbe("Succeeded", strings.Repeat("L", metadataProbeLogLimit)))
}

func TestReportScript_MetadataProbe(t *testing.T) {
	cases := []reportCase{
		{name: "carries the probe Job's pod times and log once its pod succeeded", opts: []reportOption{withK3s(k3sMetadataProbe("Succeeded", testFile("report/probe.log")))}, check: func(t *testing.T, r *reportRig) {
			got := decodeKeptProbe(t, "hardening.metadataProbe", hardeningOf(t, r.fields())["metadataProbe"])
			want := keptProbe{CheckedAt: cannedProbeFinishedAt, PodCreatedAt: cannedProbeCreatedAt, ContainerStartedAt: cannedProbeStartedAt, Log: testFile("report/probe.log")}
			failIf(t, got != want, "hardening.metadataProbe = %+v\nwant %+v, the pod's finish, creation and start times and its log", got, want)
		}},
		{name: "a bounded log of text that grows as JSON is carried in whole", opts: []reportOption{withK3s(k3sMetadataProbe("Succeeded", largestToolOutput))}, check: func(t *testing.T, r *reportRig) { assertCarriedProbeLog(t, r, nil) }},
		{name: "a NUL in the log never reaches the report", opts: []reportOption{withK3s(k3sMetadataProbe("Succeeded", "t=0s 2026-10-04T09:50:04Z: http=000 bytes=0\ntext-before-the-nul\x00text-after-the-nul\n"))}, check: func(t *testing.T, r *reportRig) {
			assertCarriedProbeLog(t, r, []string{"text-before-the-nul", "text-after-the-nul"})
		}},
	}
	for _, tc := range []struct {
		name string
		opt  fakeK3sOption
	}{
		{"the pod failed", k3sMetadataProbe("Failed", testFile("report/probe.log"))},
		{"the pod logged nothing", k3sMetadataProbe("Succeeded", "")},
		{"the Job has no pod", k3sMetadataProbe("", "")},
		{"the pods cannot be read", k3sFailing(readProbePods, 1, "Error from server (Forbidden): pods is forbidden\n")},
	} {
		cases = append(cases, reportCase{name: "carries null when " + tc.name, opts: []reportOption{withK3s(tc.opt)}, check: func(t *testing.T, r *reportRig) {
			got := string(hardeningOf(t, r.fields())["metadataProbe"])
			failIf(t, got != "null", "hardening.metadataProbe = %s, want null when %s", truncate(got, 200), tc.name)
		}})
	}
	runReportCases(t, cases)
}

func assertCarriedProbeLog(t *testing.T, r *reportRig, contains []string) {
	t.Helper()
	assertNoNUL(t, "the probe's log", r.req.Body)
	got := decodeKeptProbe(t, "hardening.metadataProbe", hardeningOf(t, reportFields(t, r.req))["metadataProbe"])
	n := jsonTextLen(got.Log)
	failIf(t, got.Log == "" || n > metadataProbeLogLimit, "hardening.metadataProbe.log is %d bytes of JSON text, want some and at most %d", n, metadataProbeLogLimit)
	failIf(t, strings.ContainsRune(got.Log, 0), "hardening.metadataProbe.log carries a NUL")
	assertNamesAll(t, "hardening.metadataProbe.log", got.Log, contains...)
}

func hardeningOf(t *testing.T, fields map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	return objectOf(t, "hardening", fields["hardening"], hardeningKeys...)
}

func patchingOf(t *testing.T, fields map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	return objectOf(t, "patching", fields["patching"], patchingKeys...)
}

func patchingFields(t *testing.T, r *reportRig) map[string]json.RawMessage {
	t.Helper()
	return patchingOf(t, reportFields(t, r.req))
}

func patchingString(t *testing.T, r *reportRig, member string) string {
	t.Helper()
	return stringOf(t, "patching."+member, patchingFields(t, r)[member])
}

type rebootState struct {
	Exists     bool    `json:"exists"`
	ModifiedAt *string `json:"modifiedAt"`
	Packages   string  `json:"packages"`
}

func reportedReboot(t *testing.T, raw []byte) rebootState {
	t.Helper()
	objectOf(t, "patching.rebootRequired", raw, "exists", "modifiedAt", "packages")
	var s rebootState
	err := json.Unmarshal(raw, &s)
	failIf(t, err != nil || strings.ContainsRune(s.Packages, 0), "patching.rebootRequired = %s, want exists a bool, modifiedAt a time or null and packages a NUL-free string (%v)", truncate(string(raw), 200), err)
	return s
}

func assertPatchingWithinBounds(t *testing.T, fields map[string]json.RawMessage) {
	t.Helper()
	patching := patchingOf(t, fields)
	for _, member := range mapKeys(patchingMemberBounds) {
		n, bound := len(patching[member]), patchingMemberBounds[member]
		failIf(t, n > bound, "patching.%s is %d bytes of JSON text in the body, want at most %d: %s", member, n, bound, truncate(string(patching[member]), 200))
	}
	for _, p := range patchingReads {
		raw := p.in(t, fields)
		n, limit := len(raw), patchingPartBounds[p.member+"."+p.part]
		failIf(t, n > limit, "patching.%s.%s is %d bytes of JSON text in the body, want at most %d", p.member, p.part, n, limit)
	}
}

type patchingRead struct{ read, member, part string }

var patchingReads = []patchingRead{
	{readKuredLog, "kured", "current"}, {readKuredPreviousLog, "kured", "previous"}, {readUpgradePlans, "upgradePlans", "plans"}, {readUpgradeJobs, "upgradePlans", "jobs"},
}

func (p patchingRead) in(t *testing.T, fields map[string]json.RawMessage) []byte {
	t.Helper()
	parts := map[string][]string{"kured": {"current", "previous"}, "upgradePlans": {"jobs", "plans"}}
	return objectOf(t, "patching."+p.member, patchingOf(t, fields)[p.member], parts[p.member]...)[p.part]
}

func assertPatchingPartsAnswered(t *testing.T, fields map[string]json.RawMessage, skip patchingRead) {
	t.Helper()
	want := map[string]string{
		"kured.current": mustJSON(testFile("report/kured.log")), "kured.previous": mustJSON(testFile("report/kured-previous.log")),
		"upgradePlans.plans": testFile("want/upgrade-plans.json"), "upgradePlans.jobs": testFile("want/upgrade-jobs.json"),
	}
	for _, p := range patchingReads {
		if p != skip {
			sameJSON(t, "patching."+p.member+"."+p.part, p.in(t, fields), want[p.member+"."+p.part])
		}
	}
}

func TestReportScript_Patching(t *testing.T) {
	changed := time.Date(2026, 10, 7, 1, 30, 21, 0, time.UTC)
	const pkgs, before, after = "linux-image-6.8.0-85-generic\nlibssl3t64\n", "text-before-the-nul", "text-after-the-nul"
	long := largestUnattendedUpgradesLog()
	check := func(t *testing.T, r *reportRig) []byte { return patchingFields(t, r)["check"] }
	cases := []reportCase{
		{name: "check carries the kept patch check as it is", opts: []reportOption{withStateDir(testFile("report/patch-check.json"))}, check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "patching.check", check(t, r), testFile("report/patch-check.json"))
		}},
		{name: "check is a new one once the kept check is an hour old", opts: []reportOption{withHourOldCheck()}, check: func(t *testing.T, r *reportRig) {
			got, _ := decodeAny(t, "patching.check", check(t, r)).(map[string]any)
			kept, _ := decodeAny(t, "the kept check", []byte(testFile("report/patch-check.json"))).(map[string]any)
			failIf(t, got == nil || got["verdict"] == nil || got["checkedAt"] == kept["checkedAt"], "patching.check = %s, want the check the collector ran in place of the hour-old one", truncate(string(check(t, r)), 200))
		}},
		{name: "autoUpgradeUnits carries whether the units are enabled", opts: []reportOption{withTool(reportSystemctlEnv, "systemctl", cannedSSHUnits, "", cannedSSHUnitsExit, toolAnswer{args: autoUpgradeUnitsArgs, stdout: "enabled\nenabled\nenabled\n"})}, check: func(t *testing.T, r *reportRig) {
			assertAutoUpgradeUnits(t, r, "enabled\nenabled\nenabled\n", 0)
		}},
		{name: "autoUpgradeUnits records a disabled timer as evidence while the report goes", opts: []reportOption{withTool(reportSystemctlEnv, "systemctl", cannedSSHUnits, "", cannedSSHUnitsExit, toolAnswer{args: autoUpgradeUnitsArgs, stdout: "enabled\ndisabled\nenabled\n", exit: 1})}, check: func(t *testing.T, r *reportRig) {
			assertAutoUpgradeUnits(t, r, "enabled\ndisabled\nenabled\n", 1)
		}},
		{name: "unattendedUpgradesLog carries all of a short log", opts: []reportOption{withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", testFile("report/unattended-upgrades.log"))}, check: func(t *testing.T, r *reportRig) {
			got := patchingString(t, r, "unattendedUpgradesLog")
			failIf(t, got != testFile("report/unattended-upgrades.log"), "patching.unattendedUpgradesLog = %q, want the whole log", got)
		}},
		{name: "unattendedUpgradesLog carries nothing when there is no log yet", opts: []reportOption{withEnvVar(reportUnattendedUpgradesLogEnv, "/nonexistent/unattended-upgrades.log")}, check: func(t *testing.T, r *reportRig) {
			got := patchingString(t, r, "unattendedUpgradesLog")
			failIf(t, got != "", "patching.unattendedUpgradesLog = %q, want nothing", got)
		}},
		{name: "unattendedUpgradesLog carries the newest whole lines of a long log within its bound", opts: []reportOption{withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", strings.Join(long, "\n")+"\n")}, check: func(t *testing.T, r *reportRig) {
			got := patchingString(t, r, "unattendedUpgradesLog")
			newest := long[len(long)-1]
			n := jsonTextLen(got)
			failIf(t, n > unattendedUpgradesLogLimit || n <= unattendedUpgradesLogLimit-jsonTextLen(newest+"\n"), "patching.unattendedUpgradesLog is %d bytes of JSON text, want the newest lines that fit in %d", n, unattendedUpgradesLogLimit)
			first := strings.SplitN(got, "\n", 2)[0]
			failIf(t, lastLine(got) != newest || !slices.Contains(long, first), "patching.unattendedUpgradesLog starts %q and ends %q, want whole lines ending with the newest %q", truncate(first, 80), truncate(lastLine(got), 80), truncate(newest, 80))
		}},
		{name: "rebootRequired carries a pending reboot's mtime and packages", opts: []reportOption{withRebootSentinel(changed, pkgs)}, check: func(t *testing.T, r *reportRig) {
			want := "2026-10-07T01:30:21Z"
			got := reportedReboot(t, patchingFields(t, r)["rebootRequired"])
			failIf(t, !got.Exists || got.ModifiedAt == nil || *got.ModifiedAt != want || got.Packages != pkgs, "patching.rebootRequired = %+v, want exists, modifiedAt %s and packages %q", got, want, pkgs)
		}},
		{name: "rebootRequired says no reboot is pending", opts: []reportOption{withEnvVar(reportRebootRequiredEnv, "/nonexistent/reboot-required")}, check: func(t *testing.T, r *reportRig) {
			got := reportedReboot(t, patchingFields(t, r)["rebootRequired"])
			failIf(t, got.Exists || got.ModifiedAt != nil || got.Packages != "", "patching.rebootRequired = %+v, want not exists, null modifiedAt and no packages", got)
		}},
		{name: "rebootRequired keeps the start of a package list past its limit", opts: []reportOption{withRebootSentinel(changed, strings.Repeat("linux-image-6.8.0-85-generic\n", 1000))}, check: func(t *testing.T, r *reportRig) {
			got := reportedReboot(t, patchingFields(t, r)["rebootRequired"])
			n := jsonTextLen(got.Packages)
			failIf(t, !got.Exists || n > rebootPackagesLimit || n < rebootPackagesLimit/2 || !strings.HasPrefix(got.Packages, "linux-image-6.8.0-85-generic\n"), "patching.rebootRequired = exists %v with %d bytes of JSON text of packages starting %q, want the start of the list within %d", got.Exists, n, truncate(got.Packages, 80), rebootPackagesLimit)
		}},
		{name: "kured carries the log of ds/kured before and after its reboot", check: func(t *testing.T, r *reportRig) {
			assertPatchingPartsAnswered(t, reportFields(t, r.req), patchingRead{})
			var current, previous bool
			for _, c := range k3sCallsOf(t, r.k3s) {
				if c.verb == "logs" && c.names("kured", "ds", "daemonset", "daemonsets") && c.flags["--namespace"] == "kube-system" {
					_, p := c.flags["--previous"]
					_, short := c.flags["-p"]
					previous, current = previous || p || short || c.flags["--previous"] == "true", current || !(p || short)
				}
			}
			failIf(t, !current || !previous, "k3s kubectl read kured's current log %v and its previous log %v, want both from ds/kured in kube-system", current, previous)
		}},
		{name: "upgradePlans carries each Plan and Job in system-upgrade", check: func(t *testing.T, r *reportRig) {
			assertPatchingPartsAnswered(t, reportFields(t, r.req), patchingRead{})
			calls := k3sCallsOf(t, r.k3s)
			for _, kinds := range [][]string{{"plans", "plan", "plans.upgrade.cattle.io", "plan.upgrade.cattle.io"}, {"jobs", "job", "jobs.batch", "job.batch"}} {
				if !slices.ContainsFunc(calls, func(c k3sCall) bool {
					return c.verb == "get" && len(c.positional) > 1 && slices.Contains(kinds, c.positional[1]) && c.flags["--namespace"] == "system-upgrade" && c.flags["--output"] == "json"
				}) {
					t.Errorf("k3s kubectl never read %s in system-upgrade as JSON; k3s ran with %q", kinds[0], r.k3s.calls(t))
				}
			}
		}},
	}
	for _, tc := range []struct{ name, content string }{
		{"not JSON", "verdict: pass\n"},
		{"a JSON list", `[{"verdict": "pass"}]`},
		{"past the limit", mustJSON(map[string]any{"verdict": "pass", "pad": strings.Repeat("p", patchCheckFileLimit)})},
		{"an empty file", ""},
		{"half a JSON object", `{"checkedAt": "2026-10-08T03:10:00Z", "verdict": "pa`},
	} {
		cases = append(cases, reportCase{name: "check says why it cannot carry a patch-check.json that is " + tc.name, opts: []reportOption{withStateDir(tc.content)}, check: func(t *testing.T, r *reportRig) {
			m := objectOf(t, "patching.check", check(t, r), "unreadable")
			why := stringOf(t, "patching.check.unreadable", m["unreadable"])
			failIf(t, strings.TrimSpace(why) == "" || len(why) > 1024, "patching.check.unreadable = %q, want a short reason", why)
		}})
	}
	for _, p := range patchingReads {
		message := "Error from server (BadRequest): previous terminated container \"kured\" in pod \"kured-x7k2p\" not found (" + p.read + ")"
		cases = append(cases, reportCase{name: "a failed " + p.member + "." + p.part + " read records its own failure and every other field reports", opts: []reportOption{withK3s(k3sFailing(p.read, 1, message+"\n"))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			assertKubectlFailure(t, "patching."+p.member+"."+p.part, p.in(t, fields), 1, message)
			assertPatchingPartsAnswered(t, fields, p)
			assertClusterAnsweredBut(t, fields, clusterRead{})
		}})
		if p.member != "upgradePlans" {
			continue
		}
		cases = append(cases, reportCase{name: "an upgradePlans." + p.part + " read that is not JSON records why", opts: []reportOption{withK3s(k3sPrinting(p.read, "NAME         IMAGE                 CHANNEL   VERSION\nk3s-server   rancher/k3s-upgrade   v1.36     \n"))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			assertKubectlFailure(t, "patching.upgradePlans."+p.part, p.in(t, fields), 0, "")
			assertPatchingPartsAnswered(t, fields, p)
		}})
	}
	const newest, draining = `time="2026-10-08T02:01:12Z" level=info msg="Commanding reboot for node: orbitdemo-abcd2345"`, `time="2026-10-08T02:00:41Z" level=info msg="Draining node orbitdemo-abcd2345"`
	for _, tc := range []struct {
		name, log string
		contains  []string
	}{
		{"far past the limit", largestToolOutput + "\n" + newest + "\n", []string{newest}},
		{"a NUL in the log", testFile("report/kured-previous.log") + before + "\x00" + after + "\n", []string{before, after}},
		{"a drain before a dozen evictions", kuredDrainLog(draining, newest), []string{draining, newest}},
	} {
		cases = append(cases, reportCase{name: "kured logs keep their end and carry no NUL: " + tc.name, opts: []reportOption{withK3s(k3sLogs(readKuredLog, tc.log), k3sLogs(readKuredPreviousLog, tc.log))}, check: func(t *testing.T, r *reportRig) {
			assertNoNUL(t, "kured's log", r.req.Body)
			kured := objectOf(t, "patching.kured", patchingFields(t, r)["kured"], "current", "previous")
			for _, part := range []string{"current", "previous"} {
				got := stringOf(t, "patching.kured."+part, kured[part])
				n := jsonTextLen(got)
				failIf(t, got == "" || n > kuredLogLimit, "patching.kured.%s is %d bytes of JSON text, want some and at most %d", part, n, kuredLogLimit)
				assertNamesAll(t, "patching.kured."+part, got, tc.contains...)
			}
		}})
	}
	for _, tc := range []struct {
		name string
		opts []reportOption
	}{
		{"the largest failing answers", []reportOption{withFailingK3s(strings.Repeat("\x01", 1<<20)), withTool(reportSystemctlEnv, "systemctl", largestToolOutput, largestToolOutput, 1),
			withStateDir(strings.Repeat("\x01é", 1<<18)), withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", strings.Repeat(strings.Repeat("\x01", 200)+"\n", 2000)),
			withRebootSentinel(time.Now(), largestToolOutput)}},
		{"the largest succeeding answers", []reportOption{withK3s(extremePatchingAnswers()...), withTool(reportSystemctlEnv, "systemctl", largestToolOutput, "", 0),
			withStateDir(largestNonASCIICheck(t)), withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", strings.Repeat(strings.Repeat("\x01", 200)+"\n", 2000)),
			withRebootSentinel(time.Now(), largestToolOutput)}},
	} {
		cases = append(cases, reportCase{name: "each patching member stays within its bound on every branch: " + tc.name, opts: tc.opts, check: func(t *testing.T, r *reportRig) {
			fatalIf(t, !json.Valid(r.req.Body), "the report body is not valid JSON")
			assertPatchingWithinBounds(t, reportFields(t, r.req))
		}})
	}
	runReportCases(t, cases)
}

func assertAutoUpgradeUnits(t *testing.T, r *reportRig, output string, exit int) {
	t.Helper()
	status, got := commandResult(t, "patching.autoUpgradeUnits", patchingFields(t, r)["autoUpgradeUnits"], autoUpgradeUnitsLimit)
	failIf(t, status != exit || got != output, "patching.autoUpgradeUnits = exitStatus %d, output %q, want %d and %q", status, got, exit, output)
	want := strings.Fields(autoUpgradeUnitsArgs)
	failIf(t, !r.tools["systemctl"].ran(t, want...), "systemctl ran with %q, want a run with %q", r.tools["systemctl"].runs(t), want)
}

func largestBody(t *testing.T, succeeding bool) []reportOption {
	t.Helper()
	journal, cloudInit := largestLogs()
	uu := largestUnattendedUpgradesLog()
	opts := []reportOption{withJournal(journal), withSource(reportCloudInitLogEnv, "cloud-init-output.log", strings.Join(cloudInit, "\n")+"\n"),
		withSource(reportUnattendedUpgradesLogEnv, "unattended-upgrades.log", strings.Join(uu, "\n")+"\n"), withLargestStateDir(t),
		withRebootSentinel(time.Now(), largestToolOutput)}
	if succeeding {
		return append(opts, withK3s(append(append(extremeClusterAnswers(), extremePatchingAnswers()...), k3sSecretsEncrypt(largestToolOutput, "", 0),
			k3sExec(ciliumStatusCommand, largestToolOutput, "", 0), k3sExec(hubbleObserveCommand, largestToolOutput, "", 0), k3sMetadataProbe("Succeeded", largestToolOutput))...),
			withTool(reportSSEnv, "ss", largestToolOutput, "", 0), withTool(reportSystemctlEnv, "systemctl", largestToolOutput, "", 0), withTool(reportNftEnv, "nft", largestToolOutput, "", 0))
	}
	return append(opts, withFailingK3s(strings.Repeat("E", 1<<20)), withTool(reportSSEnv, "ss", "", largestToolOutput, 1),
		withTool(reportSystemctlEnv, "systemctl", largestToolOutput, "", 1), withTool(reportNftEnv, "nft", "", largestToolOutput, 1))
}

func assertApplicationsKeepClippedConditions(t *testing.T, raw []byte) {
	t.Helper()
	failIf(t, len(raw) > applicationsLimit, "applications is %d bytes of JSON text, want whole entries within %d", len(raw), applicationsLimit)
	var entries []struct {
		Name       string              `json:"name"`
		Conditions []map[string]string `json:"conditions"`
	}
	err := json.Unmarshal(raw, &entries)
	fatalIf(t, err != nil || len(entries) == 0, "applications = %s (err %v), want a list of entries", truncate(string(raw), 200), err)
	for _, e := range entries {
		var i int
		_, err := fmt.Sscanf(e.Name, "application-%05d", &i)
		fatalIf(t, err != nil, "applications entry %q has no generated index: %v", truncate(e.Name, 40), err)
		long := fmt.Sprintf("comparison-%05d-", i) + strings.Repeat("m", 700)
		want := []map[string]string{
			{"type": "SharedResourceWarning", "message": fmt.Sprintf("short-%05d", i)},
			{"type": "ComparisonError", "message": long[:applicationConditionMessageLimit]},
		}
		if !reflect.DeepEqual(e.Conditions, want) {
			t.Errorf("applications entry %d conditions = %s, want the short message whole and the long one clipped to its first %d bytes", i, truncate(fmt.Sprint(e.Conditions), 300), applicationConditionMessageLimit)
			return
		}
	}
}

func TestReportScript_BodyStaysUnder256KiB(t *testing.T) {
	journal, cloudInit := largestLogs()
	assertLogs := func(t *testing.T, r *reportRig, journalBudget bool) {
		t.Helper()
		fields := reportFields(t, r.req)
		_, gotJournal := postedReport(t, r.req)
		got := lastLine(gotJournal)
		failIf(t, got != journal[len(journal)-1], "the journal ends %q, want the newest line kept", truncate(got, 80))
		if journalBudget {
			perLine := jsonTextLen(journal[0] + "\n")
			got := jsonTextLen(gotJournal)
			failIf(t, got > reportJournalBudget || got <= reportJournalBudget-perLine, "the journal is %d bytes of JSON text, want the newest lines that fit in %d, so more than %d", got, reportJournalBudget, reportJournalBudget-perLine)
		}
		gotCloudInit := stringOf(t, "cloudInit", fields["cloudInit"])
		got2 := lastLine(gotCloudInit)
		failIf(t, got2 != cloudInit[len(cloudInit)-1], "cloudInit ends %q, want the newest line kept", truncate(got2, 80))
		if journalBudget {
			return
		}
		perLine := jsonTextLen(cloudInit[0] + "\n")
		got3 := jsonTextLen(gotCloudInit)
		failIf(t, got3 > reportCloudInitBudget || got3 <= reportCloudInitBudget-perLine, "cloudInit is %d bytes of JSON text, want the newest lines that fit in %d, so more than %d", got3, reportCloudInitBudget, reportCloudInitBudget-perLine)
	}
	cases := []reportCase{
		{name: "the largest logs leave every cluster field intact", opts: []reportOption{withJournal(journal), withSource(reportCloudInitLogEnv, "cloud-init-output.log", strings.Join(cloudInit, "\n")+"\n")}, check: func(t *testing.T, r *reportRig) {
			n := len(r.req.Body)
			failIf(t, n >= reportBodyLimit, "the report body is %d bytes, want under %d", n, reportBodyLimit)
			assertLogs(t, r, true)
			assertClusterAnsweredBut(t, reportFields(t, r.req), clusterRead{})
		}},
		{name: "every field at its largest and failing", opts: largestBody(t, false), check: func(t *testing.T, r *reportRig) {
			n := len(r.req.Body)
			failIf(t, n > reportBodyMax, "the report body is %d bytes, want at most %d", n, reportBodyMax)
			assertLogs(t, r, false)
			fields := reportFields(t, r.req)
			for _, rd := range clusterReads {
				assertKubectlFailure(t, rd.name(), rd.in(t, fields), 1, "EEEE")
			}
			status, output := dryRunResult(t, fields["podSecurityDryRun"])
			failIf(t, status != 1 || !strings.Contains(output, "EEEE"), "podSecurityDryRun carries exitStatus %d and %d bytes of output, want 1 and the failed dry run's stderr", status, len(output))
			h := hardeningOf(t, fields)
			for _, c := range hardeningCommands {
				status, output := commandResult(t, "hardening."+c.field, h[c.field], c.limit)
				failIf(t, status != 1 || output == "", "hardening.%s carries exitStatus %d and %d bytes of output, want 1 and the failed command's output", c.field, status, len(output))
			}
			assertKubectlFailure(t, "hardening.kubelet", h["kubelet"], 1, "EEEE")
			sameJSON(t, "hardening.metadataProbe", h["metadataProbe"], "null")
			patching := patchingOf(t, fields)
			assertPatchingWithinBounds(t, fields)
			status2, output2 := commandResult(t, "patching.autoUpgradeUnits", patching["autoUpgradeUnits"], autoUpgradeUnitsLimit)
			failIf(t, status2 != 1 || output2 == "", "patching.autoUpgradeUnits carries exitStatus %d and %d bytes of output2, want 1 and the failed command's output2", status2, len(output2))
			log, uu := patchingString(t, r, "unattendedUpgradesLog"), largestUnattendedUpgradesLog()
			n2 := jsonTextLen(log)
			failIf(t, log == "" || n2 > unattendedUpgradesLogLimit || lastLine(log) != uu[len(uu)-1], "patching.unattendedUpgradesLog is %d bytes of JSON text ending %q, want the newest line within %d", n2, truncate(lastLine(log), 80), unattendedUpgradesLogLimit)
			reboot := reportedReboot(t, patching["rebootRequired"])
			failIf(t, !reboot.Exists || reboot.Packages == "" || jsonTextLen(reboot.Packages) > rebootPackagesLimit, "patching.rebootRequired = exists %v with %d bytes of JSON text of packages, want a pending reboot and at most %d", reboot.Exists, jsonTextLen(reboot.Packages), rebootPackagesLimit)
			for _, p := range patchingReads {
				assertKubectlFailure(t, "patching."+p.member+"."+p.part, p.in(t, fields), 1, "EEEE")
			}
			assertLargestScansCarried(t, fields)
			sameJSON(t, "dedicatedServer", fields["dedicatedServer"], largestDedicatedServerFacts(t))
		}},
		{name: "every read succeeding at its largest keeps entries and bounds", opts: largestBody(t, true), check: func(t *testing.T, r *reportRig) {
			n := len(r.req.Body)
			fatalIf(t, n > reportBodyMax || !json.Valid(r.req.Body), "the report body is %d bytes (valid JSON %v), want valid JSON of at most %d", n, json.Valid(r.req.Body), reportBodyMax)
			fields := reportFields(t, r.req)
			kubernetes := objectOf(t, "kubernetes", fields["kubernetes"], "argocdPods", "nodes")
			assertNonEmptyList(t, "kubernetes.nodes", kubernetes["nodes"])
			assertNonEmptyList(t, "kubernetes.argocdPods", kubernetes["argocdPods"])
			for _, field := range []string{"ciliumPods", "helmInstallJobs", "helmCharts", "applications", "repositorySecrets", "admission", "defaultDenyPolicies"} {
				assertNonEmptyList(t, field, fields[field])
			}
			assertApplicationsKeepClippedConditions(t, fields["applications"])
			podMemory := objectOf(t, "podMemory", fields["podMemory"], "argocd", "cilium")
			assertNonEmptyList(t, "podMemory.argocd", podMemory["argocd"])
			assertNonEmptyList(t, "podMemory.cilium", podMemory["cilium"])
			for _, b := range []struct {
				field string
				limit int
			}{{"podSecurity", podSecurityLimit}, {"subscriptionResources", subscriptionResourcesLimit}, {"cloudNativePG", cloudNativePGLimit}} {
				assertNonEmptyList(t, b.field, fields[b.field])
				n := len(fields[b.field])
				failIf(t, n > b.limit, "%s is %d bytes of JSON text, want whole entries within %d", b.field, n, b.limit)
			}
			status, _ := dryRunResult(t, fields["podSecurityDryRun"])
			failIf(t, status != 0, "podSecurityDryRun.exitStatus = %d, want 0 for a dry run that succeeded", status)
			sameJSON(t, "jwks", fields["jwks"], jwksOfLength(jwksLimit))
			h := hardeningOf(t, fields)
			for _, c := range hardeningCommands {
				status, output := commandResult(t, "hardening."+c.field, h[c.field], c.limit)
				failIf(t, status != 0 || output == "", "hardening.%s carries exitStatus %d and %d bytes of output, want 0 and the start of what it printed", c.field, status, len(output))
			}
			probe := decodeKeptProbe(t, "hardening.metadataProbe", h["metadataProbe"])
			failIf(t, probe.Log == "" || jsonTextLen(probe.Log) > metadataProbeLogLimit, "hardening.metadataProbe.log is %d bytes of JSON text, want some and at most %d", jsonTextLen(probe.Log), metadataProbeLogLimit)
			patching := patchingOf(t, fields)
			assertPatchingWithinBounds(t, fields)
			status, output := commandResult(t, "patching.autoUpgradeUnits", patching["autoUpgradeUnits"], autoUpgradeUnitsLimit)
			failIf(t, status != 0 || output == "", "patching.autoUpgradeUnits carries exitStatus %d and %d bytes of output, want 0 and the start of what it printed", status, len(output))
			log, uu := patchingString(t, r, "unattendedUpgradesLog"), largestUnattendedUpgradesLog()
			n2 := jsonTextLen(log)
			failIf(t, log == "" || n2 > unattendedUpgradesLogLimit || lastLine(log) != uu[len(uu)-1], "patching.unattendedUpgradesLog is %d bytes of JSON text ending %q, want the newest lines within %d", n2, truncate(lastLine(log), 80), unattendedUpgradesLogLimit)
			reboot := reportedReboot(t, patching["rebootRequired"])
			failIf(t, !reboot.Exists || reboot.Packages == "" || jsonTextLen(reboot.Packages) > rebootPackagesLimit, "patching.rebootRequired = exists %v with %d bytes of JSON text of packages, want a pending reboot and at most %d", reboot.Exists, jsonTextLen(reboot.Packages), rebootPackagesLimit)
			for _, part := range []string{"current", "previous"} {
				got := stringOf(t, "patching.kured."+part, objectOf(t, "patching.kured", patching["kured"], "current", "previous")[part])
				n := jsonTextLen(got)
				failIf(t, got == "" || n > kuredLogLimit, "patching.kured.%s is %d bytes of JSON text, want the end of the log within %d", part, n, kuredLogLimit)
			}
			plans := objectOf(t, "patching.upgradePlans", patching["upgradePlans"], "jobs", "plans")
			for _, b := range []struct {
				part  string
				limit int
			}{{"plans", upgradePlansLimit}, {"jobs", upgradeJobsLimit}} {
				assertNonEmptyList(t, "patching.upgradePlans."+b.part, plans[b.part])
				n := len(plans[b.part])
				failIf(t, n > b.limit, "patching.upgradePlans.%s is %d bytes of JSON text, want whole entries within %d", b.part, n, b.limit)
			}
			assertLargestScansCarried(t, fields)
		}},
		{name: "the journal shrinks to the room every other field at its bound leaves", opts: append(largestBody(t, true), withK3s(k3sFailing(readHelmCharts, 1, strings.Repeat("E", 1<<20)),
			k3sFailing(readSecrets, 1, strings.Repeat("E", 1<<20)), k3sFailing(readNamespaces, 1, strings.Repeat("E", 1<<20)), k3sFailing(readConfigz, 1, strings.Repeat("E", 1<<20)),
			k3sFailing(readJWKS, 1, strings.Repeat("E", 1<<20))), withSource(reportOSReleaseEnv, "os-release", strings.Repeat("o", 2*osReleaseLimit)),
			withLargestProbe()), check: func(t *testing.T, r *reportRig) {
			fatalIf(t, !json.Valid(r.req.Body), "the report body is not valid JSON")
			_, gotJournal := postedReport(t, r.req)
			n, kept := len(r.req.Body), jsonTextLen(gotJournal)
			rest := n - kept
			fatalIf(t, rest+reportJournalBudget <= reportBodyMax, "every other field takes %d bytes, so a %d-byte journal still fits within %d and this proves nothing", rest, reportJournalBudget, reportBodyMax)
			lines := strings.Count(gotJournal, "\n")
			fatalIf(t, n > reportBodyMax || kept >= reportJournalBudget || lines == 0 || lines >= len(journal), "the body is %d bytes and the journal %d bytes of JSON text in %d lines, want the body within %d and a journal shrunk below %d to some of the newest lines", n, kept, lines, reportBodyMax, reportJournalBudget)
			want := strings.Join(journal[len(journal)-lines:], "\n") + "\n"
			failIf(t, gotJournal != want, "the journal is not the newest %d whole lines: it ends %q", lines, truncate(lastLine(gotJournal), 80))
			next := jsonTextLen(journal[len(journal)-lines-1] + "\n")
			failIf(t, n+next <= reportBodyMax, "the body is %d bytes with room for the next %d-byte journal line within %d, want the journal to keep every line that fits", n, next, reportBodyMax)
		}},
	}
	runReportCases(t, cases)
}

func argocdOf(t *testing.T, r *reportRig) map[string]json.RawMessage {
	t.Helper()
	return objectOf(t, "argocd", r.fields()["argocd"], "ingresses", "routes", "services")
}

func wantRouteEntry(path string, a argocdAnswer) map[string]any {
	entry := map[string]any{"path": path, "status": a.Status, "bytes": len(a.Body)}
	if a.Exit != 0 {
		entry["status"], entry["bytes"], entry["error"] = 0, 0, "curl exit "+strconv.Itoa(a.Exit)
	}
	if path == argocdUserinfoPath {
		var loggedIn any
		var body map[string]any
		if a.Exit == 0 && a.Status == 200 && json.Unmarshal([]byte(a.Body), &body) == nil {
			if b, ok := body["loggedIn"].(bool); ok {
				loggedIn = b
			}
		}
		entry["loggedIn"] = loggedIn
	}
	return entry
}

func wantRoutes(answers map[string]argocdAnswer) string {
	entries := []any{}
	for _, path := range argocdRoutePaths {
		entries = append(entries, wantRouteEntry(path, answers[path]))
	}
	return mustJSON(entries)
}

func withAnswers(overrides map[string]argocdAnswer) map[string]argocdAnswer {
	answers := cannedArgoCDAnswers()
	maps.Copy(answers, overrides)
	return answers
}

func shortFlag(argv []string, letter rune) bool {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1 && strings.Trim(a[1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" && strings.ContainsRune(a, letter) {
			return true
		}
	}
	return false
}

func optionValue(argv []string, names ...string) (string, bool) {
	for i, a := range argv {
		if slices.Contains(names, a) && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}

func assertBoundedSeconds(t *testing.T, argv []string, limit float64, names ...string) {
	t.Helper()
	v, ok := optionValue(argv, names...)
	secs, err := strconv.ParseFloat(v, 64)
	failIf(t, !ok || err != nil || secs <= 0 || secs > limit, "curl %v: %v = %q, want a number of seconds above 0 and at most %v", argv, names, v, limit)
}

func TestReportScript_ArgoCDExposure(t *testing.T) {
	const unreadable = "Error from server (NotFound): services \"argocd-server\" not found\n"
	const servicesWant = `[{"name":"argocd-applicationset-controller","type":"ClusterIP"},{"name":"argocd-redis","type":"ClusterIP"},` +
		`{"name":"argocd-repo-server","type":"ClusterIP"},{"name":"argocd-server","type":"ClusterIP"},{"name":"argocd-server-public","type":"NodePort"}]`
	const ingressesWant = `[{"name":"argocd-server-ingress"}]`
	userinfo := func(status int, body string) map[string]argocdAnswer {
		return map[string]argocdAnswer{argocdUserinfoPath: {Status: status, Body: body}}
	}
	hugeAnswers := map[string]argocdAnswer{
		argocdUserinfoPath:     {Status: 200, Body: `{"loggedIn":true,"pad":"` + strings.Repeat("p", 1<<20) + `"}`},
		"/api/v1/applications": {Status: 200, Body: strings.Repeat("a", 1<<20)},
		"/api/v1/repositories": {Status: 200, Body: strings.Repeat("r", 1<<20)},
	}
	unreachable := map[string]argocdAnswer{
		"/api/v1/clusters":     {Exit: 28, Stderr: "Connection timed out"},
		"/api/v1/applications": {Exit: 7, Stderr: "Failed to connect"},
		"/api/v1/settings":     {Exit: 60, Stderr: "SSL certificate problem"},
	}
	cases := []reportCase{
		{name: "carries every unauthenticated route in order with its status and body size", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "argocd.routes", argocdOf(t, r)["routes"], wantRoutes(cannedArgoCDAnswers()))
		}},
		{name: "asks each route once at the argocd-server Service's name on port 443", check: func(t *testing.T, r *reportRig) {
			var got []string
			for _, a := range r.curl.attempts(t) {
				var urls []string
				for _, arg := range a.Argv {
					if strings.Contains(arg, "://") {
						urls = append(urls, arg)
					}
				}
				fatalIf(t, len(urls) != 1, "a probe named %d URLs in %v, want one", len(urls), a.Argv)
				got = append(got, urls[0])
			}
			var want []string
			for _, path := range argocdRoutePaths {
				want = append(want, argocdBaseURL+path)
			}
			failIf(t, !slices.Equal(got, want), "the node asked %v, want %v", got, want)
		}},
		{name: "lists Services and Ingresses of the argocd namespace as JSON", check: func(t *testing.T, r *reportRig) {
			var services, ingresses bool
			for _, c := range k3sCallsOf(t, r.k3s) {
				if c.verb != "get" || c.flags["--namespace"] != "argocd" || len(c.positional) != 2 || c.flags["--output"] != "json" {
					continue
				}
				services = services || slices.Contains([]string{"service", "services", "svc"}, c.positional[1])
				ingresses = ingresses || slices.Contains([]string{"ingress", "ingresses", "ing"}, c.positional[1])
			}
			failIf(t, !services || !ingresses, "k3s kubectl calls %v: Services list %v, Ingresses list %v, want both in -n argocd", r.k3s.calls(t), services, ingresses)
		}},
		{name: "sends no credential, follows no redirect and asks with the self-signed, https-only, bounded flags", check: func(t *testing.T, r *reportRig) {
			attempts := r.curl.attempts(t)
			fatalIf(t, len(attempts) != len(argocdRoutePaths), "the node made %d probes, want %d", len(attempts), len(argocdRoutePaths))
			for _, a := range attempts {
				line := strings.ToLower(strings.Join(a.Argv, " "))
				for _, banned := range []string{"authorization", "cookie", "bearer", "token"} {
					failIf(t, strings.Contains(line, banned), "curl %v carries %q, and a probe sends no credential", a.Argv, banned)
				}
				for _, long := range []string{"--location", "--location-trusted", "--cookie", "--cookie-jar", "--user", "--netrc", "--config", "--oauth2-bearer", "--data", "--data-binary", "--form", "--upload-file", "--fail"} {
					failIf(t, slices.Contains(a.Argv, long), "curl %v carries %s", a.Argv, long)
				}
				for _, short := range []rune{'L', 'b', 'c', 'u', 'n', 'K', 'd', 'F', 'T', 'f'} {
					failIf(t, shortFlag(a.Argv, short), "curl %v carries -%c", a.Argv, short)
				}
				header, hasHeader := optionValue(a.Argv, "-H", "--header")
				failIf(t, hasHeader && strings.HasPrefix(header, "@"), "curl %v reads headers from a file", a.Argv)
				method, hasMethod := optionValue(a.Argv, "-X", "--request")
				failIf(t, hasMethod && method != "GET", "curl %v asks with %s, want GET", a.Argv, method)
				failIf(t, !shortFlag(a.Argv, 'k') && !slices.Contains(a.Argv, "--insecure"), "curl %v lacks -k, and Argo CD's certificate is self-signed", a.Argv)
				proto, _ := optionValue(a.Argv, "--proto")
				failIf(t, proto != "=https", "curl %v has --proto %q, want =https", a.Argv, proto)
				assertBoundedSeconds(t, a.Argv, 1, "--connect-timeout")
				assertBoundedSeconds(t, a.Argv, 5, "--max-time", "-m")
				failIf(t, a.Argv[0] != "-q", "curl %v starts with %q, want -q first so curl reads no ~/.curlrc", a.Argv, a.Argv[0])
				size, hasSize := optionValue(a.Argv, "--max-filesize")
				bytes, err := strconv.ParseInt(size, 10, 64)
				failIf(t, !hasSize || err != nil || bytes <= 0 || bytes > 65536, "curl %v: --max-filesize = %q, want a byte count above 0 and at most 65536", a.Argv, size)
			}
		}},
		{name: "keeps no response text in the report beyond the loggedIn boolean", opts: []reportOption{withArgoCDAnswers(map[string]argocdAnswer{
			"/api/v1/clusters":  {Exit: 28, Stderr: argocdSentinel},
			"/api/v1/projects":  {Status: 500, Body: argocdSentinel},
			"/api/v1/gpgkeys":   {Status: 302, Body: ""},
			"/api/v1/repocreds": {Status: 200, Body: `{"items":[{"url":"` + argocdSentinel + `"}]}`},
		})}, check: func(t *testing.T, r *reportRig) {
			argocdOf(t, r)
			failIf(t, strings.Contains(strings.ToLower(string(r.req.Body)), argocdSentinel), "the posted report repeats text an Argo CD route answered with")
		}},
		{name: "records a route curl cannot reach with status 0, bytes 0 and its curl exit and still asks the rest", opts: []reportOption{withArgoCDAnswers(unreachable)}, check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "argocd.routes", argocdOf(t, r)["routes"], wantRoutes(withAnswers(unreachable)))
			failIf(t, len(r.curl.attempts(t)) != len(argocdRoutePaths), "the node asked %d routes, want all %d after some failed", len(r.curl.attempts(t)), len(argocdRoutePaths))
		}},
		{name: "lists each Service of the argocd namespace with its name and type", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "argocd.services", argocdOf(t, r)["services"], servicesWant)
		}},
		{name: "lists each Ingress of the argocd namespace by name", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "argocd.ingresses", argocdOf(t, r)["ingresses"], ingressesWant)
		}},
		{name: "reports an empty list when the argocd namespace has no Ingress", opts: []reportOption{withK3s(k3sAnswer(readArgoCDIngresses, `{"apiVersion":"v1","kind":"List","items":[]}`))}, check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "argocd.ingresses", argocdOf(t, r)["ingresses"], `[]`)
		}},
		{name: "records the kubectl failure as services and still reports routes and ingresses when the Services list fails", opts: []reportOption{withK3s(k3sFailing(readArgoCDServices, 1, "Error from server (Forbidden): services is forbidden\n"))}, check: func(t *testing.T, r *reportRig) {
			a := argocdOf(t, r)
			assertKubectlFailure(t, "argocd.services", a["services"], 1, "services is forbidden")
			sameJSON(t, "argocd.routes", a["routes"], wantRoutes(cannedArgoCDAnswers()))
			sameJSON(t, "argocd.ingresses", a["ingresses"], ingressesWant)
		}},
		{name: "records the kubectl failure as ingresses and still reports routes and services when the Ingresses list fails", opts: []reportOption{withK3s(k3sFailing(readArgoCDIngresses, 1, "Error from server (Forbidden): ingresses is forbidden\n"))}, check: func(t *testing.T, r *reportRig) {
			a := argocdOf(t, r)
			assertKubectlFailure(t, "argocd.ingresses", a["ingresses"], 1, "ingresses is forbidden")
			sameJSON(t, "argocd.routes", a["routes"], wantRoutes(cannedArgoCDAnswers()))
			sameJSON(t, "argocd.services", a["services"], servicesWant)
		}},
		{name: "keeps the report within 256 KiB with huge route answers and thousands of Services and Ingresses", opts: append(largestBody(t, true), withK3s(
			k3sGenerate(readArgoCDServices, "services", 3000, "", nil), k3sGenerate(readArgoCDIngresses, "ingresses", 3000, "", nil)),
			withArgoCDAnswers(hugeAnswers)), check: func(t *testing.T, r *reportRig) {
			n := len(r.req.Body)
			fatalIf(t, n > reportBodyMax || !json.Valid(r.req.Body), "the report body is %d bytes (valid JSON %v), want valid JSON of at most %d", n, json.Valid(r.req.Body), reportBodyMax)
			a := argocdOf(t, r)
			sameJSON(t, "argocd.routes", a["routes"], wantRoutes(withAnswers(hugeAnswers)))
			for _, part := range []string{"services", "ingresses"} {
				assertNonEmptyList(t, "argocd."+part, a[part])
				failIf(t, len(a[part]) > argocdListLimit, "argocd.%s is %d bytes of JSON text, want whole entries within %d", part, len(a[part]), argocdListLimit)
			}
		}},
		{name: "records each failed argocd read with its stderr when every k3s kubectl call fails at its largest", opts: largestBody(t, false), check: func(t *testing.T, r *reportRig) {
			n := len(r.req.Body)
			fatalIf(t, n > reportBodyMax || !json.Valid(r.req.Body), "the report body is %d bytes (valid JSON %v), want valid JSON of at most %d", n, json.Valid(r.req.Body), reportBodyMax)
			a := argocdOf(t, r)
			for _, part := range []string{"services", "ingresses"} {
				assertKubectlFailure(t, "argocd."+part, a[part], 1, "EEEE")
			}
		}},
	}
	for _, c := range []struct {
		name   string
		answer map[string]argocdAnswer
	}{
		{"true for a 200 JSON object holding loggedIn true", userinfo(200, `{"loggedIn":true,"username":"admin"}`)},
		{"false for a 200 JSON object holding loggedIn false", userinfo(200, `{"loggedIn":false}`)},
		{"null for a 200 JSON object without loggedIn", userinfo(200, `{"username":"admin"}`)},
		{"null for a 200 JSON object whose loggedIn is a string", userinfo(200, `{"loggedIn":"true"}`)},
		{"null for a 200 JSON object whose loggedIn is null", userinfo(200, `{"loggedIn":null}`)},
		{"null for a 200 JSON array", userinfo(200, `[true]`)},
		{"null for a 200 body that is not JSON", userinfo(200, `<html>login</html>`)},
		{"null for a 200 empty body", userinfo(200, ``)},
		{"null for a 401 answer that holds loggedIn true", userinfo(401, `{"loggedIn":true}`)},
		{"null for a 200 body nested 200000 arrays deep", userinfo(200, strings.Repeat("[", 200000))},
		{"null for a 200 body nested 200000 objects deep", userinfo(200, strings.Repeat(`{"a":`, 200000))},
	} {
		cases = append(cases, reportCase{name: "reads userinfo loggedIn as " + c.name, opts: []reportOption{withArgoCDAnswers(c.answer)}, check: func(t *testing.T, r *reportRig) {
			routes := argocdOf(t, r)["routes"]
			var entries []json.RawMessage
			fatalIf(t, json.Unmarshal(routes, &entries) != nil || len(entries) == 0, "argocd.routes = %s, want a list of routes", truncate(string(routes), 200))
			sameJSON(t, "argocd.routes[0]", entries[0], mustJSON(wantRouteEntry(argocdUserinfoPath, c.answer[argocdUserinfoPath])))
			sameJSON(t, "argocd.routes", routes, wantRoutes(withAnswers(c.answer)))
		}})
	}
	runReportCases(t, cases)
}

func TestArgoCDFakes_AnswerAsCurlAndKubectlDo(t *testing.T) {
	curl := newFakeArgoCDCurl(t, map[string]argocdAnswer{
		"/api/v1/a": {Status: 401, Body: "hello"},
		"/api/v1/b": {Exit: 28, Stderr: "timed out"},
	})
	run := func(args ...string) (string, int) {
		out, err := exec.Command(filepath.Join(curl.dir, "curl"), args...).Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return string(out), exit.ExitCode()
		}
		fatalIf(t, err != nil, "running the fake curl: %v", err)
		return string(out), 0
	}
	common := []string{"-sS", "-k", "--proto", "=https", "-o", "/dev/null", "-w", "%{http_code} %{size_download}"}

	out, exit := run(append(common, argocdBaseURL+"/api/v1/a")...)
	failIf(t, out != "401 5" || exit != 0, "a answered %q exit %d, want \"401 5\" exit 0", out, exit)
	out, exit = run(append(common, argocdBaseURL+"/api/v1/b")...)
	failIf(t, out != "000 0" || exit != 28, "b answered %q exit %d, want \"000 0\" exit 28", out, exit)
	out, exit = run("-sS", "--proto", "=https", argocdBaseURL+"/api/v1/a")
	failIf(t, out != "" || exit != 60, "a without -k answered %q exit %d, want nothing and exit 60", out, exit)
	out, exit = run("-sSk", argocdBaseURL+"/api/v1/a")
	failIf(t, out != "hello" || exit != 0, "a to stdout answered %q exit %d, want hello exit 0", out, exit)
	out, exit = run("-sSk", "--proto", "=https", "http://"+argocdClusterIP+"/api/v1/a")
	failIf(t, out != "" || exit != 1, "a over http answered %q exit %d, want nothing and exit 1", out, exit)
	failIf(t, len(curl.attempts(t)) != 5, "the fake logged %d probes, want 5", len(curl.attempts(t)))

	k3s := newFakeK3s(t)
	got, err := exec.Command(k3s.path, "kubectl", "get", "service", "argocd-server", "-n", "argocd", "-o", "jsonpath={.spec.clusterIP}").Output()
	failIf(t, err != nil || string(got) != argocdClusterIP, "the cluster IP read answered %q (%v), want %s", got, err, argocdClusterIP)
}

type admissionEntry struct {
	Rule       string `json:"rule"`
	Fixture    string `json:"fixture"`
	ExitStatus int    `json:"exitStatus"`
	Message    string `json:"message"`
}

func admissionOf(t *testing.T, r *reportRig) []admissionEntry {
	t.Helper()
	var entries []admissionEntry
	raw := reportFields(t, r.req)["admission"]
	fatalIf(t, json.Unmarshal(raw, &entries) != nil || entries == nil, "admission = %s, want a list", truncate(string(raw), 300))
	return entries
}

func applyCalls(t *testing.T, r *reportRig) []k3sCall {
	t.Helper()
	var out []k3sCall
	for _, c := range k3sCallsOf(t, r.k3s) {
		if c.verb == "apply" {
			out = append(out, c)
		}
	}
	return out
}

func TestReportScript_Admission(t *testing.T) {
	const rule = "mitstack-require-app-label"
	quotes := strings.Repeat(`"`, 10000)
	sixFull := map[string]string{}
	for _, name := range []string{"mitstack-disallow-host-path", rule, "mitstack-require-image-digest", "mitstack-require-resource-limits", "mitstack-restrict-image-registries", "pod-security-restricted"} {
		sixFull[name] = "apiVersion: v1\n# " + name + strings.Repeat("x", 10000) + "\n"
	}
	sixOpts := []fakeK3sOption{k3sFixtures(sixFull)}
	for name := range sixFull {
		sixOpts = append(sixOpts, k3sApplying(name, "", "Error from server: "+name+strings.Repeat("m", 10000)+"\n", 1))
	}
	cases := []reportCase{
		{name: "records each rule with its fixture, exit status and refusal message in key order", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "admission", reportFields(t, r.req)["admission"], testFile("want/admission.json"))
		}},
		{name: "applies each fixture once as a server dry run into the probe namespace", check: func(t *testing.T, r *reportRig) {
			calls := applyCalls(t, r)
			failIf(t, len(calls) != 6, "the node applied %d fixtures, want 6", len(calls))
			for _, c := range calls {
				failIf(t, c.flags["--dry-run"] != "server" || c.flags["--namespace"] != admissionNamespace || c.flags["--filename"] != "-" || c.flags["--request-timeout"] != "10s", "apply ran as %q", c.line())
			}
		}},
		{name: "dry-runs mitstack-node's own fixtures in mitstack-node after the probe namespace's", opts: []reportOption{withK3s(
			k3sNodeFixtures(map[string]string{"mitstack-verify-node-agent-signature-unsigned": "apiVersion: v1\nkind: Pod\n"}),
			k3sApplying("mitstack-verify-node-agent-signature-unsigned", "", "admission webhook denied the request\n", 1))}, check: func(t *testing.T, r *reportRig) {
			entries, calls := admissionOf(t, r), applyCalls(t, r)
			fatalIf(t, len(entries) != 7 || len(calls) != 7, "the report carries %d admission entries from %d dry runs, want 7 of each", len(entries), len(calls))
			last := entries[6]
			failIf(t, last.Rule != "mitstack-verify-node-agent-signature-unsigned" || last.ExitStatus != 1 || last.Message != "admission webhook denied the request\n", "the last entry = %+v, want the mitstack-node fixture's refusal", last)
			failIf(t, calls[6].flags["--namespace"] != "mitstack-node", "the mitstack-node fixture ran as %q, want -n mitstack-node", calls[6].line())
		}},
		{name: "records an accepted fixture with exit status 0 and what kubectl printed", opts: []reportOption{withK3s(k3sApplying("mitstack-require-image-digest", "deployment.apps/refused-require-image-digest created (server dry run)\n", "", 0))}, check: func(t *testing.T, r *reportRig) {
			for _, e := range admissionOf(t, r) {
				if e.Rule == "mitstack-require-image-digest" {
					failIf(t, e.ExitStatus != 0 || e.Message != "deployment.apps/refused-require-image-digest created (server dry run)\n", "entry = %+v, want exit 0 and the dry run's output", e)
					return
				}
			}
			t.Error("admission has no entry for mitstack-require-image-digest")
		}},
		{name: "skips a ConfigMap key outside a-z, 0-9 and hyphen and applies nothing for it", opts: []reportOption{withK3s(k3sFixtures(map[string]string{
			rule: "apiVersion: v1\n", "Upper": "apiVersion: v1\n# a\n", "under_score": "apiVersion: v1\n# b\n", "dot.ted": "apiVersion: v1\n# c\n", "with space": "apiVersion: v1\n# d\n"}))}, check: func(t *testing.T, r *reportRig) {
			entries := admissionOf(t, r)
			failIf(t, len(entries) != 1 || entries[0].Rule != rule, "admission = %+v, want only %s", entries, rule)
			failIf(t, len(applyCalls(t, r)) != 1, "the node applied %d fixtures, want 1", len(applyCalls(t, r)))
		}},
		{name: "reports an empty list and applies nothing when the ConfigMap holds no data", opts: []reportOption{withK3s(k3sFixtures(nil))}, check: func(t *testing.T, r *reportRig) {
			failIf(t, len(admissionOf(t, r)) != 0 || len(applyCalls(t, r)) != 0, "admission = %s with %d applies, want [] and none", reportFields(t, r.req)["admission"], len(applyCalls(t, r)))
		}},
		{name: "clips the fixture to 4096 bytes and the message to 2048 bytes of JSON text", opts: []reportOption{withK3s(
			k3sFixtures(map[string]string{rule: "apiVersion: v1 " + strings.Repeat("x", 10000)}), k3sApplying(rule, "", "Error: "+strings.Repeat("m", 10000), 1))}, check: func(t *testing.T, r *reportRig) {
			e := admissionOf(t, r)[0]
			failIf(t, e.Fixture != ("apiVersion: v1 " + strings.Repeat("x", 10000))[:admissionFixtureLimit] || e.Message != ("Error: " + strings.Repeat("m", 10000))[:admissionMessageLimit], "fixture is %d bytes and message %d, want the first %d and %d", len(e.Fixture), len(e.Message), admissionFixtureLimit, admissionMessageLimit)
		}},
		{name: "counts JSON text when clipping, so quotes cost two bytes each", opts: []reportOption{withK3s(k3sFixtures(map[string]string{rule: quotes}), k3sApplying(rule, "", quotes, 1))}, check: func(t *testing.T, r *reportRig) {
			e := admissionOf(t, r)[0]
			failIf(t, e.Fixture != quotes[:admissionFixtureLimit/2] || e.Message != quotes[:admissionMessageLimit/2], "fixture is %d quotes and message %d, want %d and %d", len(e.Fixture), len(e.Message), admissionFixtureLimit/2, admissionMessageLimit/2)
		}},
		{name: "reports all six rules at their largest", opts: []reportOption{withK3s(sixOpts...)}, check: func(t *testing.T, r *reportRig) {
			entries := admissionOf(t, r)
			failIf(t, len(entries) != 6, "admission holds %d entries, want all 6 rules at their largest", len(entries))
			for _, e := range entries {
				failIf(t, jsonTextLen(e.Fixture) > admissionFixtureLimit || jsonTextLen(e.Message) > admissionMessageLimit || len(e.Fixture) < admissionFixtureLimit-8 || len(e.Message) < admissionMessageLimit-8, "%s fixture %d bytes, message %d bytes, want each clipped to its limit", e.Rule, len(e.Fixture), len(e.Message))
			}
		}},
		{name: "keeps the body within 256 KiB with forty full-size fixtures", opts: []reportOption{withK3s(k3sGenerate(readAdmissionFixtures, "admissionFixtures", 40, "", nil))}, check: func(t *testing.T, r *reportRig) {
			failIf(t, len(r.req.Body) > reportBodyMax || !json.Valid(r.req.Body), "the body is %d bytes (valid %v), want valid JSON within %d", len(r.req.Body), json.Valid(r.req.Body), reportBodyMax)
			failIf(t, len(admissionOf(t, r)) < 6, "admission holds %d entries, want at least the six rules", len(admissionOf(t, r)))
		}},
		{name: "lists only mitstack-default-deny policies with their rule counts, selector, types and manager", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "defaultDenyPolicies", reportFields(t, r.req)["defaultDenyPolicies"], testFile("want/default-deny-policies.json"))
		}},
		{name: "reports [] when no namespace holds the generated policy", opts: []reportOption{withK3s(k3sAnswer(readDefaultDeny, extremeList([]any{})))}, check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "defaultDenyPolicies", reportFields(t, r.req)["defaultDenyPolicies"], `[]`)
		}},
		{name: "keeps whole defaultDenyPolicies entries within 4096 bytes", opts: []reportOption{withK3s(k3sGenerate(readDefaultDeny, "networkPolicies", 3000, "", nil))}, check: func(t *testing.T, r *reportRig) {
			raw := reportFields(t, r.req)["defaultDenyPolicies"]
			assertNonEmptyList(t, "defaultDenyPolicies", raw)
			failIf(t, len(raw) > defaultDenyLimit, "defaultDenyPolicies is %d bytes, want whole entries within %d", len(raw), defaultDenyLimit)
		}},
		{name: "lists only app namespace certificates with their Ready status, reason and message", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "certificates", reportFields(t, r.req)["certificates"], testFile("want/certificates.json"))
		}},
		{name: "lists only app namespace challenges with their DNS name, state and reason", check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "challenges", reportFields(t, r.req)["challenges"], testFile("want/challenges.json"))
		}},
		{name: "reports [] certificates and challenges when no app namespace holds one", opts: []reportOption{withK3s(
			k3sAnswer(readCertificates, extremeList([]any{certificateIn("cert-manager", "internal-ca", "True", "Ready", "fine")})),
			k3sAnswer(readChallenges, extremeList([]any{})))}, check: func(t *testing.T, r *reportRig) {
			fields := reportFields(t, r.req)
			sameJSON(t, "certificates", fields["certificates"], `[]`)
			sameJSON(t, "challenges", fields["challenges"], `[]`)
		}},
		{name: "clips a certificate's Ready message like an Application condition message", opts: []reportOption{withK3s(
			k3sAnswer(readCertificates, extremeList([]any{certificateIn("app-long", "long-tls", "False", "Failed", strings.Repeat("m", 2000))})))}, check: func(t *testing.T, r *reportRig) {
			sameJSON(t, "certificates", reportFields(t, r.req)["certificates"], mustJSON([]any{map[string]any{
				"namespace": "app-long", "name": "long-tls", "status": "False", "reason": "Failed", "message": strings.Repeat("m", applicationConditionMessageLimit)}}))
		}},
	}
	runReportCases(t, cases)
}

const (
	dedicatedServerFile  = "dedicated-server.json"
	dedicatedServerLimit = 2048

	fixtureUplink           = "enp5s0"
	fixtureVSwitchInterface = fixtureUplink + ".4000"
	fixtureVSwitchGateway   = "10.254.0.1"
)

func largestDedicatedServerFacts(t *testing.T) string {
	t.Helper()
	facts := map[string]any{"checkedAt": "2026-10-12T09:20:00Z", "tpm": true, "tpmDevices": []string{"tpm0"}, "vswitch": "dropped",
		"vswitchProbe": map[string]any{"interface": fixtureVSwitchInterface, "gateway": fixtureVSwitchGateway, "echoRequests": 3,
			"echoReplies": 0, "neighbour": "", "pingExitStatus": 1}}
	empty := len(mustJSON(facts))
	facts["vswitchProbe"].(map[string]any)["neighbour"] = strings.Repeat("S", dedicatedServerLimit-empty)
	out := mustJSON(facts)
	fatalIf(t, len(out) != dedicatedServerLimit, "the largest dedicated facts are %d bytes, want exactly the %d-byte bound", len(out), dedicatedServerLimit)
	return out
}

func TestReportScript_ACloudServerReportsNoDedicatedFacts(t *testing.T) {
	t.Parallel()
	r := newReportRig(t).send()

	got := string(r.fields()["dedicatedServer"])

	failIf(t, got != "null", "dedicatedServer = %s on a node no probe ran on, want null", truncate(got, 200))
}
