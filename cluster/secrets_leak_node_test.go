package cluster

// secrets_leak_node_test.go checks no node secret reaches a script's output, a command line or a report.

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mitstack-eu/operator-kit/v2/kittest"
)

var nodeSecrets = []string{
	fixtureEnrolmentToken,
	fixtureReportToken,
	fixtureRepositoryToken,
	fixtureNotificationToken,
	refreshedRepositoryToken,
	staleRepositoryToken,
}

func assertQuietRun(t *testing.T, who string, run enrolRun, rec *argvRecorder, reqs []recordedEnrolRequest) {
	t.Helper()
	fatalIf(t, len(reqs) == 0, "%s sent no request to its endpoint, so what it printed proves nothing:\n%s", who, run.output())
	lines := rec.commandLines(t)
	fatalIf(t, !strings.Contains(lines, "curl "), "the recorder saw no curl command line from %s, so it saw nothing the script ran:\n%s", who, lines)

	kittest.AssertNoSecret(t, who+"'s stdout", run.stdout, nodeSecrets...)
	kittest.AssertNoSecret(t, who+"'s stderr", run.stderr, nodeSecrets...)
	kittest.AssertNoSecret(t, "a command line "+who+" ran", lines, nodeSecrets...)
	for _, req := range reqs {
		failIf(t, !req.SawClient, "%s: no process command line carried its endpoint URL while its request was open; want the scan to have seen the client", who)
		for _, line := range req.TokenOnCmdline {
			t.Errorf("%s: a process command line carried the bearer token it presents while its request was open: %s", who, line)
		}
	}
	assertNothingLeftHolding(t, who, run.tmp, nodeSecrets)
}

func TestNoSecretLeak_NodeTokensThroughEnrolmentRefusalRefreshAndReport(t *testing.T) {
	_, err := os.ReadFile("/proc/self/cmdline")
	fatalIf(t, err != nil, "reading /proc/self/cmdline error = %v; want it readable, since this check scans process command lines", err)
	ud, cc := renderFixture(t)
	kittest.AssertNoSecret(t, "the user data, apart from the enrolment token in enrolment.env",
		strings.ReplaceAll(cc.allText(ud), fixtureEnrolmentToken, ""), nodeSecrets...)
	enrolScript := cc.enrolScript(t).Content
	env := cc.file(t, "/etc/mitstack/"+enrolScriptEnvFile).Content

	refused := newFakeEnrolment(t, fixtureEnrolmentToken, http.StatusFailedDependency)
	refused.answerStatusWith(http.StatusFailedDependency, `{"error":"`+githubRefusal+`"}`)
	rec := newArgvRecorder(t)
	run := runEnrolScript(t, enrolScript, env, refused.endpoint(), refused.caFile, enrolRefusalBound, withPATH(rec.path()))

	assertExitedNonZero(t, "a 424", run)
	assertQuietRun(t, "the refused enrol script", run, rec, refused.received())

	// Its directories are reused by the refresh and report steps below.
	enrolled := newFakeEnrolment(t, fixtureEnrolmentToken, http.StatusOK)
	enrolled.answerOKWith(tokenAnswer(t, fixtureRepositoryToken, fixtureReportToken))
	rec = newArgvRecorder(t)
	run = runEnrolScript(t, enrolScript, env, enrolled.endpoint(), enrolled.caFile, enrolRefusalBound, withPATH(rec.path()))

	fatalIf(t, run.err != nil, "the enrol script on a 200 error = %v; want nil\n%s", run.err, run.output())
	assertQuietRun(t, "the enrol script", run, rec, enrolled.received())
	_, err = os.Stat(filepath.Join(run.manifests, notificationSecretFile))
	fatalIf(t, err != nil, "stat %s after the enrol script on a 200 error = %v; want the notification token written to the node's files", notificationSecretFile, err)
	enrolmentDir := run.dir

	refresh := runRefresh(t, fixtureReportToken, []int{http.StatusOK}, "")
	fatalIf(t, refresh.run.err != nil, "the refresh on a 200 error = %v; want nil\n%s", refresh.run.err, refresh.run.output())
	assertQuietRun(t, "the refresh", refresh.run, refresh.rec, refresh.srv.received())
	failed := runRefresh(t, fixtureReportToken, []int{http.StatusServiceUnavailable}, "")
	assertExitedNonZero(t, "a 503", failed.run)
	assertQuietRun(t, "the failed refresh", failed.run, failed.rec, failed.srv.received())

	report := newFakeEnrolment(t, fixtureReportToken, http.StatusOK)
	rec = newArgvRecorder(t)
	argocd := newFakeArgoCDCurl(t, cannedArgoCDAnswers())
	run = runReportScript(t, enrolmentDir, fixtureReportToken, report.URL+reportEndpointPath, report.caFile,
		newFakeJournal(t, cannedJournal).path, withPATH(argocd.dir+string(os.PathListSeparator)+rec.path()))

	fatalIf(t, run.err != nil, "the report script on a 200 error = %v; want nil\n%s", run.err, run.output())
	reqs := report.received()
	assertQuietRun(t, "the report script", run, rec, reqs)
	for _, req := range reqs {
		kittest.AssertNoSecret(t, "the report body", string(req.Body), nodeSecrets...)
	}
	want := map[string]any{"repositoryToken": redactedValue, "repositoryTokenExpiresAt": redactedValue, "reportToken": redactedValue, "notificationToken": redactedValue}
	got := decodeAny(t, "enrolment", reportFields(t, reqs[len(reqs)-1])["enrolment"])
	failIf(t, !reflect.DeepEqual(got, want), "the report's enrolment = %v; want %v", got, want)
}
