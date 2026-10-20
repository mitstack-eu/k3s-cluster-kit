package cluster

// The in-cluster report carries every field path the host report of release 3.0.0 carried, over the same fakes.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

// fieldPaths lists every path into a JSON value, with [] for any list element.
func fieldPaths(prefix string, v any, into map[string]bool) {
	into[prefix] = true
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			fieldPaths(prefix+"."+k, child, into)
		}
	case []any:
		for _, child := range x {
			fieldPaths(prefix+"[]", child, into)
		}
	}
}

func bodyPaths(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var v any
	testutil.FatalIf(t, json.Unmarshal(body, &v) != nil, "a report body is not JSON")
	paths := map[string]bool{}
	fieldPaths("", v, paths)
	return paths
}

func TestReportScript_CarriesEveryFieldPathOfTheHostReport(t *testing.T) {
	hostReport := strings.NewReplacer("@OS_PATCH_UNITS@", osPatchUnits, "@SCAN_SHA256@", strings.Repeat("0", 64)).Replace(testutil.TestRepoFile(t, "testdata/host-report-3.0.0.sh"))
	srv := testutil.NewFakeEnrolment(t, testutil.FixtureReportToken, http.StatusOK)
	k3s := newFakeK3s(t)
	env := append(defaultEvidenceEnv(t), testutil.ReportScriptURLEnv+"="+srv.URL+testutil.ReportEndpointPath, testutil.EnrolScriptDirEnv+"="+enrolledDir(t, enrolledAnswer(t)),
		testutil.ReportJournalctlEnv+"="+newFakeJournal(t, cannedJournal).path, testutil.ReportK3sEnv+"="+k3s.path)
	host := testutil.RunSh(t, "host-report", hostReport, reportRunBound, testutil.EnrolRun{Tmp: t.TempDir()}, env, srv.CAFile,
		[]testutil.ScriptRunOption{withPathPrefix(newFakeArgoCDCurlAt(t, "https://"+argocdClusterIP+":443", cannedArgoCDAnswers()).dir)})
	testutil.FatalIf(t, host.Err != nil || len(srv.Received()) != 1, "the host report failed or sent %d reports: %v\n%s", len(srv.Received()), host.Err, host.Output())

	inCluster := newReportRig(t).send()

	before, after := bodyPaths(t, srv.Received()[0].Body), bodyPaths(t, inCluster.req.Body)
	var missing []string
	for path := range before {
		if !after[path] {
			missing = append(missing, path)
		}
	}
	slices.Sort(missing)
	testutil.FailIf(t, len(missing) > 0, "the in-cluster report lacks %d field paths the host report carried: %v", len(missing), missing)
}
