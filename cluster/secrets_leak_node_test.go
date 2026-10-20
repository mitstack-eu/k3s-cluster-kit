package cluster

// secrets_leak_node_test.go checks no node secret reaches a script's output, a command line or a report.

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
	"github.com/mitstack-eu/operator-kit/v2/kittest"
)

var nodeSecrets = []string{
	testutil.FixtureEnrolmentToken,
	testutil.FixtureReportToken,
	testutil.FixtureRepositoryToken,
	testutil.FixtureNotificationToken,
	refreshedRepositoryToken,
	staleRepositoryToken,
}

func assertQuietRun(t *testing.T, who string, run testutil.EnrolRun, rec *argvRecorder, reqs []testutil.RecordedEnrolRequest) {
	t.Helper()
	testutil.FatalIf(t, len(reqs) == 0, "%s sent no request to its endpoint, so what it printed proves nothing:\n%s", who, run.Output())
	lines := rec.commandLines(t)
	testutil.FatalIf(t, !strings.Contains(lines, "curl "), "the recorder saw no curl command line from %s, so it saw nothing the script ran:\n%s", who, lines)

	kittest.AssertNoSecret(t, who+"'s stdout", run.Stdout, nodeSecrets...)
	kittest.AssertNoSecret(t, who+"'s stderr", run.Stderr, nodeSecrets...)
	kittest.AssertNoSecret(t, "a command line "+who+" ran", lines, nodeSecrets...)
	for _, req := range reqs {
		testutil.FailIf(t, !req.SawClient, "%s: no process command line carried its endpoint URL while its request was open; want the scan to have seen the client", who)
		for _, line := range req.TokenOnCmdline {
			t.Errorf("%s: a process command line carried the bearer token it presents while its request was open: %s", who, line)
		}
	}
	assertNothingLeftHolding(t, who, run.Tmp, nodeSecrets)
}

func TestNoSecretLeak_NodeTokensThroughEnrolmentRefusalRefreshAndReport(t *testing.T) {
	_, err := os.ReadFile("/proc/self/cmdline")
	testutil.FatalIf(t, err != nil, "reading /proc/self/cmdline error = %v; want it readable, since this check scans process command lines", err)
	ud, cc := renderFixture(t)
	kittest.AssertNoSecret(t, "the user data, apart from the enrolment token in enrolment.env",
		strings.ReplaceAll(cc.AllText(ud), testutil.FixtureEnrolmentToken, ""), nodeSecrets...)
	enrolScript := cc.EnrolScript(t).Content
	env := cc.File(t, "/etc/mitstack/"+testutil.EnrolScriptEnvFile).Content

	refused := testutil.NewFakeEnrolment(t, testutil.FixtureEnrolmentToken, http.StatusFailedDependency)
	refused.AnswerStatusWith(http.StatusFailedDependency, `{"error":"`+githubRefusal+`"}`)
	rec := newArgvRecorder(t)
	run := runEnrolScript(t, enrolScript, env, refused.Endpoint(), refused.CAFile, enrolRefusalBound, withPATH(rec.path()))

	assertExitedNonZero(t, "a 424", run)
	assertQuietRun(t, "the refused enrol script", run, rec, refused.Received())

	// Its directories are reused by the refresh and report steps below.
	enrolled := testutil.NewFakeEnrolment(t, testutil.FixtureEnrolmentToken, http.StatusOK)
	enrolled.AnswerOKWith(testutil.TokenAnswer(t, testutil.FixtureRepositoryToken, testutil.FixtureReportToken))
	rec = newArgvRecorder(t)
	run = runEnrolScript(t, enrolScript, env, enrolled.Endpoint(), enrolled.CAFile, enrolRefusalBound, withPATH(rec.path()))

	testutil.FatalIf(t, run.Err != nil, "the enrol script on a 200 error = %v; want nil\n%s", run.Err, run.Output())
	assertQuietRun(t, "the enrol script", run, rec, enrolled.Received())
	_, err = os.Stat(filepath.Join(run.Manifests, notificationSecretFile))
	testutil.FatalIf(t, err != nil, "stat %s after the enrol script on a 200 error = %v; want the notification token written to the node's files", notificationSecretFile, err)
	enrolmentDir := run.Dir

	refresh := runRefresh(t, testutil.FixtureReportToken, []int{http.StatusOK}, "")
	testutil.FatalIf(t, refresh.run.Err != nil, "the refresh on a 200 error = %v; want nil\n%s", refresh.run.Err, refresh.run.Output())
	assertQuietRun(t, "the refresh", refresh.run, refresh.rec, refresh.srv.Received())
	failed := runRefresh(t, testutil.FixtureReportToken, []int{http.StatusServiceUnavailable}, "")
	assertExitedNonZero(t, "a 503", failed.run)
	assertQuietRun(t, "the failed refresh", failed.run, failed.rec, failed.srv.Received())

	report := testutil.NewFakeEnrolment(t, testutil.FixtureReportToken, http.StatusOK)
	rec = newArgvRecorder(t)
	argocd := newFakeArgoCDCurl(t, cannedArgoCDAnswers())
	run = runReportScript(t, enrolmentDir, testutil.FixtureReportToken, report.URL+testutil.ReportEndpointPath, report.CAFile,
		newFakeJournal(t, cannedJournal).path, withPATH(argocd.dir+string(os.PathListSeparator)+rec.path()))

	testutil.FatalIf(t, run.Err != nil, "the report script on a 200 error = %v; want nil\n%s", run.Err, run.Output())
	reqs := report.Received()
	assertQuietRun(t, "the report script", run, rec, reqs)
	for _, req := range reqs {
		kittest.AssertNoSecret(t, "the report body", string(req.Body), nodeSecrets...)
	}
	want := map[string]any{"repositoryToken": testutil.RedactedValue, "repositoryTokenExpiresAt": testutil.RedactedValue, "reportToken": testutil.RedactedValue, "notificationToken": testutil.RedactedValue}
	got := decodeAny(t, "enrolment", reportFields(t, reqs[len(reqs)-1])["enrolment"])
	testutil.FailIf(t, !reflect.DeepEqual(got, want), "the report's enrolment = %v; want %v", got, want)
}
