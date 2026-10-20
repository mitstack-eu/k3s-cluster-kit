package cluster

// The node report starts the image's scan script as a detached unit, and carries each kept summary within its bound.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	scanRunnerLimit     = 2048
	reportSystemdRunEnv = "MITSTACK_SYSTEMD_RUN"
)

// withStateDirFiles is a state directory holding each named file, as the patch check and the scans leave it.
func withStateDirFiles(files map[string]string) reportOption {
	return func(r *reportRig) {
		dir := r.t.TempDir()
		for name, content := range files {
			testutil.WriteIn(r.t, dir, name, content, 0o600)
		}
		r.env = append(r.env, withEnv(testutil.ReportStateDirEnv, dir))
	}
}

// fakeScanners are the fake kube-bench, the directory of the fake kubescape and the directory of the fake systemd-run.
type fakeScanners struct {
	bench           testutil.FakeTool
	scape, launcher string
}

// withFakeScanners points the scan script at fakes printing the canned kube-bench and kubescape output, launched by a
// systemd-run that runs the unit in the foreground.
func withFakeScanners(t *testing.T) (reportOption, fakeScanners) {
	t.Helper()
	f := fakeScanners{bench: testutil.NewFakeTool(t, "kube-bench", testFile("scan/kube-bench.json"), "", 0),
		scape: fakeKubescape(t, testFile("scan/kubescape.json")), launcher: t.TempDir()}
	testutil.WriteIn(t, f.launcher, "systemd-run", testFile("fakes/systemd-run.sh"), 0o755)
	return func(r *reportRig) {
		r.env = append(r.env, withEnv(scanKubeBenchEnv, f.bench.Path), withEnv(scanKubescapeEnv, filepath.Join(f.scape, "kubescape")),
			withEnv(scanKubeconfigEnv, filepath.Join(r.t.TempDir(), "k3s.yaml")), withEnv(scanURLEnv, closedHTTPURL(r.t)+"/"),
			withEnv(scanRawURLEnv, closedHTTPURL(r.t)+"/"), withEnv(reportSystemdRunEnv, filepath.Join(f.launcher, "systemd-run")))
	}, f
}

func (f fakeScanners) ran(t *testing.T) bool {
	t.Helper()
	return len(f.bench.Runs(t)) > 0 || fakeKubescapeRan(t, f.scape)
}

func (f fakeScanners) launchArgs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.launcher, "args"))
	if os.IsNotExist(err) {
		return nil
	}
	testutil.FatalIf(t, err != nil, "reading the fake systemd-run's arguments: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// largestScanSummary is a kept summary of exactly the report's file bound whose JSON text the report re-encodes within its text bound.
func largestScanSummary(tool string) string {
	head := `{"tool":"` + tool + `","failed":[`
	var b strings.Builder
	b.WriteString(head)
	for b.Len()+len(`"aaaaaa",`)+len(`"a"]}`) < scanSummaryLimit {
		b.WriteString(`"aaaaaa",`)
	}
	return b.String() + `"` + strings.Repeat("a", scanSummaryLimit-b.Len()-len(`""]}`)) + `"]}`
}

type securityScansMember struct {
	Runner, LastRun, KubeBench, Kubescape json.RawMessage
}

func securityScansOf(t *testing.T, fields map[string]json.RawMessage) securityScansMember {
	t.Helper()
	raw := testutil.ObjectOf(t, "securityScans", fields["securityScans"], "kubeBench", "kubescape", "lastRun", "runner")
	return securityScansMember{Runner: raw["runner"], LastRun: raw["lastRun"], KubeBench: raw["kubeBench"], Kubescape: raw["kubescape"]}
}

func TestReportScript_SecurityScans(t *testing.T) {
	scanners, launched := withFakeScanners(t)
	busy, busyScanners := withFakeScanners(t)
	cases := []reportCase{
		{name: "starts the image's scan script as a detached unit and carries both summaries", opts: []reportOption{scanners}, check: func(t *testing.T, r *reportRig) {
			m := securityScansOf(t, r.fields())
			status, output := commandResult(t, "securityScans.runner", m.Runner, scanRunnerLimit)
			testutil.FailIf(t, status != 0 || !strings.Contains(output, "Running as unit: mitstack-scan.service"), "securityScans.runner carries exitStatus %d and %q, want 0 and the unit systemd-run started", status, output)
			args := launched.launchArgs(t)
			testutil.FatalIf(t, len(args) < 3, "systemd-run ran with %q", args)
			for _, want := range [][]string{{"--no-block"}, {"--collect"}, {"--unit=mitstack-scan"}, {"-p", "RuntimeMaxSec=3h"}} {
				testutil.FailIf(t, !containsRun(args, want), "systemd-run ran with %q, want %q among them, so the report never waits for a scan", args, want)
			}
			script := args[len(args)-1]
			testutil.FailIf(t, !slices.Equal(args[len(args)-3:len(args)-1], []string{"python3", "-I"}) || filepath.Base(script) != "scan.py", "systemd-run ran %q, want python3 -I on the kept scan.py", args)
			kept, err := os.ReadFile(script)
			testutil.FailIf(t, err != nil || strings.TrimSuffix(string(kept), "\n") != strings.TrimSuffix(testutil.TestRepoFile(t, "scripts/mitstack-scan.py"), "\n"), "the unit runs %s, which does not hold the image's scan script (%v)", script, err)
			last := testutil.ObjectOf(t, "securityScans.lastRun", m.LastRun, "exitStatus", "finishedAt", "output")
			testutil.FailIf(t, !strings.Contains(string(last["output"]), "kube-bench: ran; kubescape: ran") || string(last["exitStatus"]) != "0", "securityScans.lastRun is %s, want both scans run and exit status 0", m.LastRun)
			bench := testutil.ObjectOf(t, "securityScans.kubeBench", m.KubeBench, "failed", "finishedAt", "kubernetesVersion", "profile", "startedAt", "tool", "totals", "version")
			testutil.FailIf(t, string(bench["profile"]) != `"k3s-cis-1.11"`, "securityScans.kubeBench.profile = %s, want the named k3s-cis-1.11", bench["profile"])
			scape := testutil.ObjectOf(t, "securityScans.kubescape", m.Kubescape, "complianceScore", "controlsVersion", "failed", "failedControlsBySeverity", "finishedAt", "framework", "startedAt", "tool", "version")
			testutil.FailIf(t, string(scape["framework"]) != `"NSA"`, "securityScans.kubescape.framework = %s, want NSA", scape["framework"])
		}},
		{name: "reports at once when a scan is still running", opts: []reportOption{busy,
			withTool(reportSystemdRunEnv, "systemd-run", "", "Failed to start transient service unit: Unit mitstack-scan.service was already loaded or has a fragment file.\n", 1)}, check: func(t *testing.T, r *reportRig) {
			m := securityScansOf(t, r.fields())
			status, output := commandResult(t, "securityScans.runner", m.Runner, scanRunnerLimit)
			testutil.FailIf(t, status != 1 || !strings.Contains(output, "already loaded"), "securityScans.runner carries exitStatus %d and %q, want systemd-run's refusal", status, output)
			testutil.FailIf(t, busyScanners.ran(t), "a scanner ran while systemd-run refused a second unit")
			testutil.FailIf(t, string(m.LastRun) != "null", "securityScans.lastRun is %s, want null before any run finished", m.LastRun)
		}},
		{name: "carries a kept summary at its bound whole", opts: []reportOption{withStateDirFiles(map[string]string{
			kubeBenchSummaryFile: largestScanSummary("kube-bench"), kubescapeSummaryFile: largestScanSummary("kubescape")})}, check: func(t *testing.T, r *reportRig) {
			m := securityScansOf(t, r.fields())
			sameJSON(t, "securityScans.kubeBench", m.KubeBench, largestScanSummary("kube-bench"))
			sameJSON(t, "securityScans.kubescape", m.Kubescape, largestScanSummary("kubescape"))
		}},
		{name: "says a kept summary past its bound is unreadable", opts: []reportOption{withStateDirFiles(map[string]string{
			kubeBenchSummaryFile: largestScanSummary("kube-bench") + " ", kubescapeSummaryFile: "[]"})}, check: func(t *testing.T, r *reportRig) {
			m := securityScansOf(t, r.fields())
			sameJSON(t, "securityScans.kubeBench", m.KubeBench, `{"unreadable": "kube-bench.json is past 16384 bytes"}`)
			sameJSON(t, "securityScans.kubescape", m.Kubescape, `{"unreadable": "kubescape.json is not a JSON object"}`)
		}},
	}
	runReportCases(t, cases)
}

func fakeKubescapeRan(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, "args"))
	return err == nil
}

// withLargestStateDir holds the largest patch check, both scan summaries and the dedicated server's facts at their bound.
func withLargestStateDir(t *testing.T) reportOption {
	t.Helper()
	return withStateDirFiles(map[string]string{patchCheckFile: largestNonASCIICheck(t),
		kubeBenchSummaryFile: largestScanSummary("kube-bench"), kubescapeSummaryFile: largestScanSummary("kubescape"),
		testutil.DedicatedServerFile: largestDedicatedServerFacts(t)})
}

func assertLargestScansCarried(t *testing.T, fields map[string]json.RawMessage) {
	t.Helper()
	m := securityScansOf(t, fields)
	for _, tool := range []string{"kube-bench", "kubescape"} {
		testutil.FailIf(t, len(largestScanSummary(tool)) != scanSummaryLimit, "the largest %s summary is %d bytes, want exactly the %d-byte bound", tool, len(largestScanSummary(tool)), scanSummaryLimit)
	}
	sameJSON(t, "securityScans.kubeBench", m.KubeBench, largestScanSummary("kube-bench"))
	sameJSON(t, "securityScans.kubescape", m.Kubescape, largestScanSummary("kubescape"))
	status, output := commandResult(t, "securityScans.runner", m.Runner, scanRunnerLimit)
	testutil.FailIf(t, status != 1 || output == "", "securityScans.runner carries exitStatus %d and %q, want 1 and why no scan ran", status, output)
}
