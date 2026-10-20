package cluster

// The scan script runs kube-bench and kubescape on the node and keeps a bounded summary of each.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	scanKubeBenchEnv  = "MITSTACK_KUBE_BENCH"
	scanKubescapeEnv  = "MITSTACK_KUBESCAPE"
	scanKubeconfigEnv = "MITSTACK_KUBECONFIG"
	scanURLEnv        = "MITSTACK_SCAN_URL"
	scanRawURLEnv     = "MITSTACK_SCAN_RAW_URL"

	kubeBenchSummaryFile = "kube-bench.json"
	kubescapeSummaryFile = "kubescape.json"
	scanSummaryLimit     = 16384
	scanFailedLimit      = 12000
	scanResourcesLimit   = 4000
	scanErrorLimit       = 1000
	pinnedProfile        = "k3s-cis-1.11"
	scanRunBound         = 60 * time.Second
)

var (
	wantKubeBenchArgs = []string{"run", "--config-dir", "", "--benchmark", pinnedProfile, "--targets", "master,etcd,controlplane,node,policies", "--json"}
	scanTimeShape     = testutil.MadeAtShape
)

type kubeBenchSummary struct {
	Tool              string         `json:"tool"`
	Version           string         `json:"version"`
	StartedAt         string         `json:"startedAt"`
	FinishedAt        string         `json:"finishedAt"`
	Profile           string         `json:"profile"`
	KubernetesVersion string         `json:"kubernetesVersion"`
	Totals            map[string]int `json:"totals"`
	Failed            []benchFailure `json:"failed"`
	Error             *string        `json:"error"`
}

type benchFailure struct {
	ID     string `json:"id"`
	Scored bool   `json:"scored"`
	Text   string `json:"text"`
}

type kubescapeSummary struct {
	Tool                     string             `json:"tool"`
	Version                  string             `json:"version"`
	StartedAt                string             `json:"startedAt"`
	FinishedAt               string             `json:"finishedAt"`
	Framework                string             `json:"framework"`
	ControlsVersion          string             `json:"controlsVersion"`
	ComplianceScore          *float64           `json:"complianceScore"`
	FailedControlsBySeverity map[string]int     `json:"failedControlsBySeverity"`
	Failed                   []kubescapeControl `json:"failed"`
	Error                    *string            `json:"error"`
}

type kubescapeControl struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Severity        string            `json:"severity"`
	FailedResources int               `json:"failedResources"`
	Resources       []failingWorkload `json:"resources"`
}

type failingWorkload struct {
	Namespace *string `json:"namespace"`
	Kind      string  `json:"kind"`
	Name      string  `json:"name"`
}

// scanRig runs the seeded scan script against a fake k3s and fake tools, as the report does on a node.
type scanRig struct {
	t         *testing.T
	state     string
	k3sOpts   []fakeK3sOption
	kubeBench testutil.FakeTool
	kubescape string // the directory of the fake kubescape and the framework files beside it
	env       []string
	out       string
	err       error
}

func newScanRig(t *testing.T) *scanRig {
	t.Helper()
	r := &scanRig{t: t, state: t.TempDir()}
	r.kubeBench = testutil.NewFakeTool(t, "kube-bench", testFile("scan/kube-bench.json"), "", 0)
	r.kubescape = fakeKubescape(t, testFile("scan/kubescape.json"))
	return r
}

func fakeKubescape(t *testing.T, report string) string {
	t.Helper()
	dir := t.TempDir()
	testutil.WriteIn(t, dir, "kubescape", testFile("fakes/kubescape.sh"), 0o755)
	testutil.WriteIn(t, dir, "report.json", report, 0o600)
	testutil.WriteIn(t, dir, "nsa", `{"name": "NSA", "controls": []}`, 0o600)
	testutil.WriteIn(t, dir, "default_config_inputs", testFile("scan/default_config_inputs"), 0o600)
	return dir
}

func failKubescape(t *testing.T, dir, stderr string, exit int) {
	t.Helper()
	testutil.WriteIn(t, dir, "stderr", stderr, 0o600)
	testutil.WriteIn(t, dir, "exit", fmt.Sprint(exit), 0o600)
}

func (r *scanRig) run() *scanRig {
	t := r.t
	t.Helper()
	k := newFakeK3s(t, r.k3sOpts...)
	env := append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir(),
		testutil.ReportStateDirEnv + "=" + r.state, testutil.ReportK3sEnv + "=" + k.path, scanKubeconfigEnv + "=" + filepath.Join(t.TempDir(), "k3s.yaml"),
		scanKubeBenchEnv + "=" + r.kubeBench.Path, scanKubescapeEnv + "=" + filepath.Join(r.kubescape, "kubescape"),
		scanURLEnv + "=" + closedHTTPURL(t) + "/", scanRawURLEnv + "=" + closedHTTPURL(t) + "/"}, r.env...)
	script := testutil.WriteTemp(t, "mitstack-scan.py", testutil.TestRepoFile(t, "scripts/mitstack-scan.py"))
	cmd := exec.Command("python3", "-I", script)
	cmd.Env = env
	done := make(chan struct{})
	var out []byte
	go func() { out, r.err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(scanRunBound):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the scan script did not finish within %s", scanRunBound)
	}
	r.out = string(out)
	return r
}

func (r *scanRig) withEnv(kv ...string) *scanRig { r.env = append(r.env, kv...); return r }

func (r *scanRig) summaryFile(name string) (string, bool) {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.state, name))
	if os.IsNotExist(err) {
		return "", false
	}
	testutil.FatalIf(r.t, err != nil, "reading %s: %v", name, err)
	return string(raw), true
}

func (r *scanRig) kubeBenchSummary() kubeBenchSummary {
	r.t.Helper()
	raw, ok := r.summaryFile(kubeBenchSummaryFile)
	testutil.FatalIf(r.t, !ok, "the scan kept no %s; output:\n%s", kubeBenchSummaryFile, r.out)
	var s kubeBenchSummary
	testutil.FatalIf(r.t, json.Unmarshal([]byte(raw), &s) != nil, "%s is not the summary JSON: %s", kubeBenchSummaryFile, testutil.Truncate(raw, 400))
	return s
}

func (r *scanRig) kubescapeSummary() kubescapeSummary {
	r.t.Helper()
	raw, ok := r.summaryFile(kubescapeSummaryFile)
	testutil.FatalIf(r.t, !ok, "the scan kept no %s; output:\n%s", kubescapeSummaryFile, r.out)
	var s kubescapeSummary
	testutil.FatalIf(r.t, json.Unmarshal([]byte(raw), &s) != nil, "%s is not the summary JSON: %s", kubescapeSummaryFile, testutil.Truncate(raw, 400))
	return s
}

func (r *scanRig) kubescapeArgs() []string {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.kubescape, "args"))
	if os.IsNotExist(err) {
		return nil
	}
	testutil.FatalIf(r.t, err != nil, "reading the fake kubescape's arguments: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// cannedBenchFailures are the FAIL results the canned kube-bench output holds, in its order.
func cannedBenchFailures(t *testing.T, raw string) []benchFailure {
	t.Helper()
	var out struct {
		Controls []struct {
			Tests []struct {
				Results []struct {
					TestNumber string `json:"test_number"`
					TestDesc   string `json:"test_desc"`
					Status     string `json:"status"`
					Scored     bool   `json:"scored"`
				} `json:"results"`
			} `json:"tests"`
		} `json:"Controls"`
	}
	testutil.FatalIf(t, json.Unmarshal([]byte(raw), &out) != nil, "the canned kube-bench output is not JSON")
	var failed []benchFailure
	for _, c := range out.Controls {
		for _, g := range c.Tests {
			for _, res := range g.Results {
				if res.Status == "FAIL" {
					failed = append(failed, benchFailure{ID: res.TestNumber, Scored: res.Scored, Text: res.TestDesc})
				}
			}
		}
	}
	return failed
}

func assertScanTimes(t *testing.T, what, started, finished string, before, after time.Time) {
	t.Helper()
	for _, v := range []string{started, finished} {
		testutil.FatalIf(t, !scanTimeShape.MatchString(v), "%s carries the time %q, want UTC to the second", what, v)
		at, _ := time.Parse(time.RFC3339, v)
		testutil.FailIf(t, at.Before(before.Truncate(time.Second)) || at.After(after), "%s carries %s, want a time inside the run %s to %s", what, v, before.Format(time.RFC3339), after.Format(time.RFC3339))
	}
	testutil.FailIf(t, finished < started, "%s finished at %s, before it started at %s", what, finished, started)
}

func TestScanScript_KubeBenchRunsTheNamedK3sProfileAndKeepsEveryFailedCheck(t *testing.T) {
	before := time.Now().UTC()
	r := newScanRig(t).run()
	after := time.Now().UTC()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	runs := r.kubeBench.Runs(t)
	testutil.FatalIf(t, len(runs) != 1, "kube-bench ran %d times, want once", len(runs))
	got := slices.Clone(runs[0])
	testutil.FatalIf(t, len(got) != len(wantKubeBenchArgs), "kube-bench ran with %q, want %q with the config directory", got, wantKubeBenchArgs)
	got[2] = ""
	testutil.FailIf(t, !slices.Equal(got, wantKubeBenchArgs), "kube-bench ran with %q, want %q, naming the profile since kube-bench never picks one for k3s", runs[0], wantKubeBenchArgs)

	s := r.kubeBenchSummary()
	testutil.FailIf(t, s.Tool != "kube-bench" || s.Version != "v0.16.0", "the summary names %s %s, want kube-bench v0.16.0", s.Tool, s.Version)
	testutil.FailIf(t, s.Profile != pinnedProfile || s.KubernetesVersion != "v1.36.3+k3s1", "the summary names profile %q for Kubernetes %q, want %s for the node's v1.36.3+k3s1", s.Profile, s.KubernetesVersion, pinnedProfile)
	assertScanTimes(t, "the kube-bench summary", s.StartedAt, s.FinishedAt, before, after)
	testutil.FailIf(t, s.Error != nil, "the summary carries the error %q, want none", deref(s.Error))
	wantTotals := map[string]int{"pass": 69, "fail": 3, "warn": 46, "info": 14}
	testutil.FailIf(t, fmt.Sprint(s.Totals) != fmt.Sprint(wantTotals), "the summary's totals are %v, want the run's %v", s.Totals, wantTotals)
	want := cannedBenchFailures(t, testFile("scan/kube-bench.json"))
	testutil.FailIf(t, !slices.Equal(s.Failed, want), "the summary lists the failed checks %v, want every FAIL of the run %v", s.Failed, want)
	testutil.FailIf(t, !strings.Contains(r.out, "kube-bench: ran"), "the scan printed %q, want it to say kube-bench ran", r.out)
	assertLastRun(t, r, 0, "mitstack-scan: kube-bench: ran; kubescape: ran")
}

// assertLastRun checks scan-run.json, which the detached run leaves for the next report.
func assertLastRun(t *testing.T, r *scanRig, exit int, says string) {
	t.Helper()
	raw, ok := r.summaryFile("scan-run.json")
	testutil.FatalIf(t, !ok, "the scan kept no scan-run.json")
	var last struct {
		FinishedAt string `json:"finishedAt"`
		ExitStatus int    `json:"exitStatus"`
		Output     string `json:"output"`
	}
	testutil.FatalIf(t, json.Unmarshal([]byte(raw), &last) != nil, "scan-run.json is not JSON: %s", testutil.Truncate(raw, 200))
	testutil.FailIf(t, !scanTimeShape.MatchString(last.FinishedAt) || last.ExitStatus != exit || !strings.Contains(last.Output, says),
		"scan-run.json is %s, want a UTC finish time, exit status %d and output naming %q", raw, exit, says)
}

func TestScanScript_KubescapeScansNSAWithNoExceptionAndNoHostSensor(t *testing.T) {
	before := time.Now().UTC()
	r := newScanRig(t).run()
	after := time.Now().UTC()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	args := r.kubescapeArgs()
	testutil.FatalIf(t, len(args) < 3 || !slices.Equal(args[:3], []string{"scan", "framework", "nsa"}), "kubescape ran with %q, want scan framework nsa", args)
	for _, want := range [][]string{
		{"--use-from", filepath.Join(r.kubescape, "nsa")},
		{"--host-scan=false"},
		{"--format", "json"},
	} {
		testutil.FailIf(t, !containsRun(args, want), "kubescape ran with %q, want %q among them", args, want)
	}
	exceptions, err := os.ReadFile(filepath.Join(r.kubescape, "exceptions.seen"))
	testutil.FatalIf(t, err != nil, "kubescape was handed no --exceptions file: %v", err)
	testutil.FailIf(t, strings.TrimSpace(string(exceptions)) != "[]", "kubescape read the exceptions %q, want the empty list, since only the platform may exempt", exceptions)
	var inputs, wantInputs map[string]any
	seen, err := os.ReadFile(filepath.Join(r.kubescape, "controls-config.seen"))
	testutil.FatalIf(t, err != nil || json.Unmarshal(seen, &inputs) != nil, "kubescape was handed no controls config JSON: %v", err)
	var defaults struct {
		Settings struct {
			PostureControlInputs map[string]any `json:"postureControlInputs"`
		} `json:"settings"`
	}
	testutil.FatalIf(t, json.Unmarshal([]byte(testFile("scan/default_config_inputs")), &defaults) != nil, "the canned control inputs are not JSON")
	wantInputs = defaults.Settings.PostureControlInputs
	testutil.FailIf(t, testutil.MustJSON(inputs) != testutil.MustJSON(wantInputs), "kubescape read the control inputs %s, want the framework's postureControlInputs", testutil.Truncate(string(seen), 200))

	s := r.kubescapeSummary()
	testutil.FailIf(t, s.Tool != "kubescape" || s.Version != "v4.0.15" || s.Framework != "NSA" || s.ControlsVersion != "v2.0.38",
		"the summary names %s %s, framework %s at %s, want kubescape v4.0.15, NSA at v2.0.38", s.Tool, s.Version, s.Framework, s.ControlsVersion)
	assertScanTimes(t, "the kubescape summary", s.StartedAt, s.FinishedAt, before, after)
	testutil.FailIf(t, s.Error != nil, "the summary carries the error %q, want none", deref(s.Error))
	testutil.FailIf(t, s.ComplianceScore == nil, "the summary carries no compliance score")
	wantCounts := map[string]int{"criticalSeverity": 0, "highSeverity": 2, "mediumSeverity": 8, "lowSeverity": 1}
	testutil.FailIf(t, fmt.Sprint(s.FailedControlsBySeverity) != fmt.Sprint(wantCounts), "the summary counts %v failed controls by severity, want %v", s.FailedControlsBySeverity, wantCounts)
	testutil.FatalIf(t, len(s.Failed) != 11, "the summary lists %d failed controls, want all 11", len(s.Failed))
	ns := "kube-system"
	wantHigh := []kubescapeControl{
		{ID: "C-0270", Name: "Ensure CPU limits are set", Severity: "High", FailedResources: 3, Resources: []failingWorkload{
			{&ns, "Deployment", "coredns"}, {&ns, "Deployment", "local-path-provisioner"}, {&ns, "Deployment", "metrics-server"}}},
		{ID: "C-0271", Name: "Ensure memory limits are set", Severity: "High", FailedResources: 2, Resources: []failingWorkload{
			{&ns, "Deployment", "local-path-provisioner"}, {&ns, "Deployment", "metrics-server"}}},
	}
	testutil.FailIf(t, testutil.MustJSON(s.Failed[:2]) != testutil.MustJSON(wantHigh), "the summary's High controls are %s, want %s with each failing workload", testutil.MustJSON(s.Failed[:2]), testutil.MustJSON(wantHigh))
	for _, c := range s.Failed[2:] {
		testutil.FailIf(t, c.Severity == "High" || c.Severity == "Critical", "control %s is %s but listed after the Medium ones", c.ID, c.Severity)
		testutil.FailIf(t, len(c.Resources) != 0, "the %s control %s lists %d resources, want none below High", c.Severity, c.ID, len(c.Resources))
	}
}

func containsRun(args, run []string) bool {
	for i := 0; i+len(run) <= len(args); i++ {
		if slices.Equal(args[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

func TestScanScript_RunsEachScanOnlyWhenItIsDue(t *testing.T) {
	ok := `{"tool":"kube-bench","startedAt":"2026-10-08T00:00:00Z","finishedAt":"2026-10-08T00:00:01Z"}`
	failed := `{"tool":"kube-bench","startedAt":"2026-10-08T00:00:00Z","finishedAt":"2026-10-08T00:00:01Z","error":"RuntimeError: boom"}`
	cases := []struct {
		name    string
		kept    string
		age     time.Duration
		wantRun bool
	}{
		{"with no summary kept", "", 0, true},
		{"a minute after a clean run", ok, time.Minute, false},
		{"23 hours after a clean run", ok, 23 * time.Hour, false},
		{"25 hours after a clean run", ok, 25 * time.Hour, true},
		{"30 minutes after a failed run", failed, 30 * time.Minute, false},
		{"two hours after a failed run", failed, 2 * time.Hour, true},
		{"after a summary that is not JSON", "{", time.Minute, true},
		{"after a clean summary dated an hour ahead, as a clock stepped back leaves it", ok, -time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newScanRig(t)
			if c.kept != "" {
				for _, name := range []string{kubeBenchSummaryFile, kubescapeSummaryFile} {
					path := testutil.WriteIn(t, r.state, name, c.kept, 0o600)
					at := time.Now().Add(-c.age)
					testutil.FatalIf(t, os.Chtimes(path, at, at) != nil, "setting the summary's age")
				}
			}
			r.run()
			testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)
			ranBench, ranScape := len(r.kubeBench.Runs(t)) > 0, r.kubescapeArgs() != nil
			testutil.FailIf(t, ranBench != c.wantRun || ranScape != c.wantRun, "kube-bench ran %v and kubescape ran %v, want both %v", ranBench, ranScape, c.wantRun)
			if !c.wantRun {
				got, _ := r.summaryFile(kubeBenchSummaryFile)
				testutil.FailIf(t, got != c.kept, "a scan that was not due rewrote its summary to %s", testutil.Truncate(got, 200))
				testutil.FailIf(t, !strings.Contains(r.out, "kube-bench: not due"), "the scan printed %q, want it to say kube-bench was not due", r.out)
			}
		})
	}
}

func TestScanScript_AClusterThatDoesNotAnswerIsNotScanned(t *testing.T) {
	r := newScanRig(t)
	r.k3sOpts = append(r.k3sOpts, k3sFailing(readNodes, 1, "The connection to the server 127.0.0.1:6443 was refused"))
	r.run()

	testutil.FailIf(t, r.err == nil, "the scan script exited 0 with a cluster that does not answer, want a failure")
	testutil.FailIf(t, !strings.Contains(r.out, "the cluster does not answer") || !strings.Contains(r.out, "was refused"), "the scan printed %q, want it to say the cluster does not answer and why", r.out)
	for _, name := range []string{kubeBenchSummaryFile, kubescapeSummaryFile} {
		_, kept := r.summaryFile(name)
		testutil.FailIf(t, kept, "the scan kept %s with no cluster to scan", name)
	}
	testutil.FailIf(t, len(r.kubeBench.Runs(t)) != 0 || r.kubescapeArgs() != nil, "a tool ran against a cluster that does not answer")
	assertLastRun(t, r, 1, "the cluster does not answer")
}

func TestScanScript_KubernetesOlderThanTheProfileCoversIsKeptAsAnError(t *testing.T) {
	r := newScanRig(t)
	r.k3sOpts = append(r.k3sOpts, k3sAnswer(readNodes, strings.ReplaceAll(testFile("k3s/nodes.json"), "v1.36.3+k3s1", "v1.28.15+k3s1")))
	r.run()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	s := r.kubeBenchSummary()
	testutil.FatalIf(t, s.Error == nil, "the summary carries no error for Kubernetes v1.28, which no pinned profile covers")
	testutil.FailIf(t, !strings.Contains(*s.Error, "no pinned k3s-cis profile covers Kubernetes v1.28.15+k3s1"), "the summary's error is %q, want it to name the uncovered version", deref(s.Error))
	testutil.FailIf(t, len(r.kubeBench.Runs(t)) != 0, "kube-bench ran against a version no pinned profile covers")
	testutil.FailIf(t, !strings.Contains(r.out, "kube-bench: failed:"), "the scan printed %q, want it to say kube-bench failed", r.out)
}

func TestScanScript_AToolThatFailsIsKeptAsAnErrorWithItsStderr(t *testing.T) {
	r := newScanRig(t)
	r.kubeBench = testutil.NewFakeTool(t, "kube-bench", "", strings.Repeat("x", 2000)+"unable to read the journal\n", 2)
	failKubescape(t, r.kubescape, "failed to list pods\n", 3)
	r.run()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	bench, scape := r.kubeBenchSummary(), r.kubescapeSummary()
	testutil.FatalIf(t, bench.Error == nil || scape.Error == nil, "a failed tool left no error in its summary")
	testutil.FailIf(t, !strings.Contains(*bench.Error, "kube-bench exited 2") || !strings.Contains(*bench.Error, "unable to read the journal"), "kube-bench's error is %q, want its exit status and the end of its stderr", deref(bench.Error))
	testutil.FailIf(t, len(deref(bench.Error)) > scanErrorLimit, "kube-bench's error is %d characters, want at most %d", len(deref(bench.Error)), scanErrorLimit)
	testutil.FailIf(t, !strings.Contains(*scape.Error, "kubescape exited 3") || !strings.Contains(*scape.Error, "failed to list pods"), "kubescape's error is %q, want its exit status and stderr", deref(scape.Error))
	testutil.FailIf(t, bench.Failed != nil || scape.Failed != nil, "a failed run lists failed checks")
}

func TestScanScript_ADownloadWithAnotherDigestIsNeverRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not the pinned release\n")) }))
	t.Cleanup(srv.Close)
	r := newScanRig(t).withEnv(scanURLEnv+"="+srv.URL+"/", scanRawURLEnv+"="+srv.URL+"/", scanKubeBenchEnv+"=", scanKubescapeEnv+"=")
	r.run()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	for _, c := range []struct{ file, pinned string }{
		{kubeBenchSummaryFile, "sha256:82dbc7e598740dc9344d41f8ad0b8210d57c4c00bdb2c5f1d8a69a2b98baddcf"},
		{kubescapeSummaryFile, "sha256:011569dbcde85afc96cf63262e4f967166b6680fd70a623e9065334b6767b244"},
	} {
		raw, ok := r.summaryFile(c.file)
		testutil.FatalIf(t, !ok, "the scan kept no %s", c.file)
		testutil.FailIf(t, !strings.Contains(raw, "want "+c.pinned), "%s is %s, want an error naming the pinned digest %s", c.file, testutil.Truncate(raw, 300), c.pinned)
	}
	entries, err := os.ReadDir(filepath.Join(r.state, "scan-tools"))
	testutil.FatalIf(t, err != nil, "reading the tools directory: %v", err)
	for _, e := range entries {
		testutil.FailIf(t, e.IsDir() && !strings.HasPrefix(e.Name(), "."), "the tools directory keeps %s after its digest did not match", e.Name())
	}
}

func TestScanScript_SummariesStayWithinTheirBoundsAtAnySize(t *testing.T) {
	r := newScanRig(t)
	r.kubeBench = testutil.NewFakeTool(t, "kube-bench", largestKubeBenchOutput(), "", 0)
	r.kubescape = fakeKubescape(t, largestKubescapeOutput())
	r.run()
	testutil.FatalIf(t, r.err != nil, "the scan script failed: %v\n%s", r.err, r.out)

	for _, name := range []string{kubeBenchSummaryFile, kubescapeSummaryFile} {
		raw, _ := r.summaryFile(name)
		testutil.FailIf(t, len(raw) >= scanSummaryLimit, "%s is %d bytes, want under the report's %d-byte bound", name, len(raw), scanSummaryLimit)
	}
	bench := r.kubeBenchSummary()
	testutil.FailIf(t, len(bench.Failed) == 0 || len(testutil.MustJSON(bench.Failed)) > scanFailedLimit, "the kube-bench summary lists %d failed checks in %d bytes, want some within %d", len(bench.Failed), len(testutil.MustJSON(bench.Failed)), scanFailedLimit)
	testutil.FailIf(t, bench.Totals["fail"] <= len(bench.Failed), "the kube-bench totals count %d failures, want more than the %d listed, so a reader can tell the list is cut", bench.Totals["fail"], len(bench.Failed))
	for _, f := range bench.Failed {
		testutil.FailIf(t, len(f.Text) > 160, "check %s carries %d characters of text, want at most 160", f.ID, len(f.Text))
	}
	scape := r.kubescapeSummary()
	testutil.FatalIf(t, len(scape.Failed) == 0, "the kubescape summary lists no failed control")
	testutil.FailIf(t, scape.Failed[0].Severity != "Critical", "the kubescape summary lists %s first, want the Critical controls first", scape.Failed[0].Severity)
	for _, c := range scape.Failed {
		testutil.FailIf(t, len(testutil.MustJSON(c.Resources)) > scanResourcesLimit, "control %s lists %d bytes of resources, want at most %d", c.ID, len(testutil.MustJSON(c.Resources)), scanResourcesLimit)
		testutil.FailIf(t, len(c.Resources) >= c.FailedResources, "control %s lists %d of %d failing resources, want the list cut and the count kept", c.ID, len(c.Resources), c.FailedResources)
	}
}

// largestKubeBenchOutput fails every one of 400 checks, each with a description far past the kept length.
func largestKubeBenchOutput() string {
	var results []map[string]any
	for i := range 400 {
		results = append(results, map[string]any{"test_number": fmt.Sprintf("9.%d", i), "test_desc": strings.Repeat("d", 900), "status": "FAIL", "scored": true, "type": ""})
	}
	return testutil.MustJSON(map[string]any{
		"Controls": []any{map[string]any{"id": "9", "tests": []any{map[string]any{"section": "9.1", "results": results}}}},
		"Totals":   map[string]int{"total_pass": 0, "total_fail": 400, "total_warn": 0, "total_info": 0},
	})
}

// largestKubescapeOutput fails 40 Critical controls on 500 workloads each.
func largestKubescapeOutput() string {
	controls := map[string]any{}
	var results, resources []any
	for w := range 500 {
		id := fmt.Sprintf("apps/v1/ns-%03d/Deployment/workload-%s-%03d", w, strings.Repeat("w", 40), w)
		var hits []any
		for c := range 40 {
			hits = append(hits, map[string]any{"controlID": fmt.Sprintf("C-%04d", c), "status": map[string]any{"status": "failed"}, "severity": "Critical"})
		}
		results = append(results, map[string]any{"resourceID": id, "controls": hits})
		resources = append(resources, map[string]any{"resourceID": id, "object": map[string]any{"kind": "Deployment",
			"metadata": map[string]any{"namespace": fmt.Sprintf("ns-%03d", w), "name": fmt.Sprintf("workload-%s-%03d", strings.Repeat("w", 40), w)}}})
	}
	for c := range 40 {
		controls[fmt.Sprintf("C-%04d", c)] = map[string]any{"controlID": fmt.Sprintf("C-%04d", c), "name": strings.Repeat("n", 200), "status": "failed",
			"severity": "Critical", "ResourceCounters": map[string]int{"failedResources": 500}}
	}
	return testutil.MustJSON(map[string]any{
		"summaryDetails": map[string]any{"controls": controls, "complianceScore": 0.0,
			"controlsSeverityCounters": map[string]int{"criticalSeverity": 40, "highSeverity": 0, "mediumSeverity": 0, "lowSeverity": 0}},
		"metadata": map[string]any{"scanMetadata": map[string]any{"kubescapeVersion": "v4.0.15"}},
		"results":  results, "resources": resources,
	})
}

func deref(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}
