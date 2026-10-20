package cluster

import (
	"cmp"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

var (
	shebangRe  = regexp.MustCompile(`^#!\s*(/bin/sh|/usr/bin/env\s+sh)(\s+-[A-Za-z]+)?\s*$`)
	jqRe       = regexp.MustCompile(`(^|[\s;|&(!])jq(\s|$)`)
	curlCallRe = regexp.MustCompile(`(^|[\s;|&(!])curl(\s|$)`)
	headerFile = regexp.MustCompile(`(-H|--header)(\s+|=)["']?@`)
)

func assertScriptShape(t *testing.T, what string, f testutil.CloudFile, others map[string]string) {
	t.Helper()
	assertRootScript(t, what, f)
	shebang := testutil.FirstLine(f.Content)
	testutil.FailIf(t, !shebangRe.MatchString(shebang), "%s starts with %q, want a POSIX sh shebang such as #!/bin/sh", what, shebang)
	for _, other := range testutil.MapKeys(others) {
		testutil.FailIf(t, f.Path == others[other], "%s path = %s; want it apart from the path of %s", what, f.Path, other)
	}
	testutil.FailIf(t, jqRe.MatchString(f.Content), "%s runs jq, which stock ubuntu-24.04 does not have", what)
}

func assertTokenOffCurlLines(t *testing.T, what, script, tokenWord string, tokenVars ...string) {
	t.Helper()
	joined := strings.ReplaceAll(script, "\\\n", " ")
	assign := regexp.MustCompile(`(?m)^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=[^\n]*` + tokenWord)
	for _, m := range assign.FindAllStringSubmatch(joined, -1) {
		tokenVars = append(tokenVars, m[1])
	}
	var curlLines []string
	for _, line := range strings.Split(joined, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && curlCallRe.MatchString(line) {
			curlLines = append(curlLines, strings.TrimSpace(line))
		}
	}
	fromFile := false
	for _, line := range curlLines {
		for _, v := range tokenVars {
			testutil.FailIf(t, regexp.MustCompile(`\$\{?`+regexp.QuoteMeta(v)+`\b`).MatchString(line), "%s: a curl command line expands $%s, which holds a token: %s", what, v, line)
		}
		testutil.FailIf(t, strings.Contains(line, "Authorization") || strings.Contains(strings.ToLower(line), "bearer"), "%s: a curl command line builds the Authorization header itself: %s", what, line)
		fromFile = fromFile || headerFile.MatchString(line)
	}
	testutil.FailIf(t, !fromFile, "%s: no curl command line reads a header from a file (curl -H @file): %q", what, curlLines)
}

func manifestNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	testutil.FatalIf(t, err != nil, "reading the manifests directory: %v", err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func assertOnlyManifests(t *testing.T, who, manifests, output string, names ...string) map[string][]byte {
	t.Helper()
	want := slices.Sorted(slices.Values(names))
	got := manifestNames(t, manifests)
	testutil.FatalIf(t, !slices.Equal(got, want), "after %s the manifests directory holds %v, want exactly %v\n%s", who, got, want, output)
	files := map[string][]byte{}
	for _, name := range want {
		path := filepath.Join(manifests, name)
		info, err := os.Stat(path)
		testutil.FatalIf(t, err != nil, "stat %s: %v", name, err)
		perm := info.Mode().Perm()
		testutil.FailIf(t, perm != 0o600, "%s mode = %#o after %s, want 0600", name, perm, who)
		if files[name], err = os.ReadFile(path); err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
	}
	return files
}

func assertStringData(t *testing.T, file string, secret map[string]any, identity, want map[string]any, secretKey, secretValue string) {
	t.Helper()
	got := map[string]any{
		"apiVersion": secret["apiVersion"], "kind": secret["kind"],
		"name": testutil.Dig(secret, "metadata", "name"), "namespace": testutil.Dig(secret, "metadata", "namespace"),
	}
	if _, labelled := identity["secret-type label"]; labelled {
		got["secret-type label"] = testutil.Dig(secret, "metadata", "labels", "argocd.argoproj.io/secret-type")
	}
	testutil.AssertValues(t, file, got, identity)
	_, has := secret["data"]
	testutil.FailIf(t, has, "%s carries data, want the credential in stringData alone", file)
	stringData, ok := secret["stringData"].(map[string]any)
	testutil.FatalIf(t, !ok, "%s stringData is %T, want a mapping", file, secret["stringData"])
	rest := maps.Clone(stringData)
	delete(rest, secretKey)
	testutil.AssertValues(t, file+" stringData", rest, want)
	switch value, isString := stringData[secretKey].(string); {
	case !isString:
		t.Errorf("%s stringData %s is %T, want the token as a string", file, secretKey, stringData[secretKey])
	case value != secretValue:
		t.Errorf("%s stringData %s is not the token verbatim: %d bytes, want %d", file, secretKey, len(value), len(secretValue))
	}
}

func assertRepositorySecret(t *testing.T, raw []byte, wantURL, wantToken string) {
	t.Helper()
	var secret map[string]any
	err := json.Unmarshal(raw, &secret)
	testutil.FatalIf(t, err != nil, "%s is not JSON: %v", repoCredentialFile, err)
	assertStringData(t, repoCredentialFile, secret,
		map[string]any{"apiVersion": "v1", "kind": "Secret", "name": "cluster-repository", "namespace": "argocd", "secret-type label": "repository"},
		map[string]any{"type": "git", "url": wantURL, "username": repositoryTokenUsername}, "password", wantToken)
}

func assertNotificationSecret(t *testing.T, raw []byte, wantToken string) {
	t.Helper()
	assertStringData(t, notificationSecretFile, testutil.YamlMap(t, notificationSecretFile, string(raw)),
		map[string]any{"apiVersion": "v1", "kind": "Secret", "name": "argocd-notifications-secret", "namespace": "argocd"},
		map[string]any{}, "platform-token", wantToken)
}

func assertExitedNonZero(t *testing.T, why string, run testutil.EnrolRun) {
	t.Helper()
	var exit *exec.ExitError
	testutil.FatalIf(t, !errors.As(run.Err, &exit), "the script must exit non-zero on %s, got err=%v\n%s", why, run.Err, run.Output())
}

func assertNoEnrolmentJSON(t *testing.T, why string, run testutil.EnrolRun) {
	t.Helper()
	_, err := os.Stat(filepath.Join(run.Dir, testutil.EnrolScriptJSONFile))
	testutil.FailIf(t, err == nil, "the enrol script wrote %s despite %s", testutil.EnrolScriptJSONFile, why)
}

func TestEnrolScript_Contract(t *testing.T) {
	_, cc := renderFixture(t)
	enrol := cc.EnrolScript(t)
	rows := []struct {
		name  string
		check func(t *testing.T)
	}{
		{"is a root-only POSIX shell script apart from the others", func(t *testing.T) {
			assertScriptShape(t, "the enrol script", enrol, map[string]string{"the node script": cc.NodeScript(t).Path, "the verified installer": cc.Installer(t).Path})
		}},
		{"defaults to the platform endpoint, /etc/mitstack and the k3s manifests dir", func(t *testing.T) {
			testutil.AssertNamesAll(t, "the enrol script", enrol.Content, "https://api.mitstack.dev"+testutil.EnrolEndpointPath, "/etc/mitstack",
				enrolScriptURLEnv, testutil.EnrolScriptDirEnv, testutil.EnrolScriptEnvFile, testutil.EnrolScriptJSONFile,
				testutil.EnrolManifestsDirDefault, testutil.EnrolManifestsDirEnv, repoCredentialFile, "MITSTACK_REPOSITORY_URL", "python3")
		}},
		{"keeps the enrolment token off every curl command line", func(t *testing.T) {
			assertTokenOffCurlLines(t, "the enrol script", enrol.Content, "MITSTACK_ENROLMENT_TOKEN", "MITSTACK_ENROLMENT_TOKEN")
		}},
		{"writes the notification Secret through a dot-named partial", func(t *testing.T) {
			testutil.AssertNamesAll(t, "the enrol script", enrol.Content, "/."+notificationSecretFile)
		}},
	}
	for _, r := range rows {
		t.Run(r.name, r.check)
	}
}

type enrolCase struct {
	name     string
	statuses []int // nil plays an endpoint nothing listens on
	prepare  func(srv *testutil.FakeEnrolment)
	bound    time.Duration
	quiet    bool
	check    func(t *testing.T, o enrolOutcome)
}

type enrolOutcome struct {
	run    testutil.EnrolRun
	srv    *testutil.FakeEnrolment
	sleeps *sleepRecorder
	script string
}

func (o enrolOutcome) failed(t *testing.T, why string, wantRequests int) {
	t.Helper()
	assertExitedNonZero(t, why, o.run)
	assertNoEnrolmentJSON(t, why, o.run)
	names := manifestNames(t, o.run.Manifests)
	testutil.FailIf(t, len(names) != 0, "the enrol script left %v in the manifests directory despite %s", names, why)
	n := len(o.srv.Received())
	testutil.FailIf(t, wantRequests >= 0 && n != wantRequests, "the enrol script sent %d requests on %s, want exactly %d", n, why, wantRequests)
}

func (o enrolOutcome) wrote(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(o.run.Dir, testutil.EnrolScriptJSONFile)
	got, err := os.ReadFile(path)
	testutil.FatalIf(t, err != nil || string(got) != body, "%s = %q (err %v), want the 200 body unparsed, %q\n%s", testutil.EnrolScriptJSONFile, got, err, body, o.run.Output())
	info, err := os.Stat(path)
	testutil.FailIf(t, err != nil || info.Mode().Perm() != 0o600, "%s mode = %v (err %v), want 0600", testutil.EnrolScriptJSONFile, info, err)
}

func TestEnrolScript_AgainstTheEnrolmentEndpoint(t *testing.T) {
	answered := testutil.TokenAnswer(t, testutil.FixtureRepositoryToken, testutil.FixtureReportToken)
	okWith := func(body string) func(*testutil.FakeEnrolment) {
		return func(s *testutil.FakeEnrolment) { s.AnswerOKWith(body) }
	}
	ok, busy := []int{http.StatusOK}, []int{http.StatusServiceUnavailable}
	backoff := []string{"1", "2", "4", "8", "16"}
	refused := func(status int) enrolCase {
		return enrolCase{name: "a " + strconv.Itoa(status) + " fails at once and is not retried", statuses: []int{status}, quiet: status == 404,
			check: func(t *testing.T, o enrolOutcome) { o.failed(t, "a "+strconv.Itoa(status), 1) }}
	}
	cases := []enrolCase{
		{name: "a 200 writes the exact body to enrolment.json with mode 0600", statuses: ok, quiet: true, check: func(t *testing.T, o enrolOutcome) {
			testutil.FatalIf(t, o.run.Err != nil, "the enrol script failed on a 200: %v\n%s", o.run.Err, o.run.Output())
			n := len(o.srv.Received())
			testutil.FailIf(t, n != 1, "the enrol script sent %d requests for one enrolment answered 200, want 1", n)
			o.wrote(t, testutil.EnrolResponseBody)
		}},
		{name: "a 200 posts the subscription id with the bearer token and writes the three Secrets and the node agent's namespace", statuses: ok, prepare: okWith(answered), quiet: true, check: func(t *testing.T, o enrolOutcome) {
			testutil.FatalIf(t, o.run.Err != nil, "the enrol script failed on a 200: %v\n%s", o.run.Err, o.run.Output())
			reqs := o.srv.Received()
			testutil.FatalIf(t, len(reqs) != 1, "the enrol script sent %d requests, want 1\n%s", len(reqs), o.run.Output())
			req := reqs[0]
			testutil.FailIf(t, req.Method != http.MethodPost || req.Path != testutil.EnrolEndpointPath || req.ContentType != "application/json", "the request was %s %s as %q, want POST %s as application/json", req.Method, req.Path, req.ContentType, testutil.EnrolEndpointPath)
			want := "Bearer " + testutil.FixtureEnrolmentToken
			testutil.FailIf(t, req.Authorization != want, "the Authorization header is not Bearer and the token from %s (%d characters received)", testutil.EnrolScriptEnvFile, len(req.Authorization))
			var body map[string]any
			err := json.Unmarshal(req.Body, &body)
			testutil.FailIf(t, err != nil || !maps.Equal(body, map[string]any{"subscriptionId": testutil.FixtureSubID}), "request body = %s (err %v), want exactly {subscriptionId: %s}", req.Body, err, testutil.FixtureSubID)
			o.wrote(t, answered)
			files := assertOnlyManifests(t, "a 200", o.run.Manifests, o.run.Output(), repoCredentialFile, notificationSecretFile, "05-report-token.yaml", "04-mitstack-node.yaml")
			assertRepositorySecret(t, files[repoCredentialFile], testutil.FixtureRepoURL, testutil.FixtureRepositoryToken)
			testutil.FailIf(t, strings.Contains(string(files[repoCredentialFile]), "sshPrivateKey"), "%s still carries an sshPrivateKey", repoCredentialFile)
			assertNotificationSecret(t, files[notificationSecretFile], testutil.FixtureNotificationToken)
			sameJSON(t, "05-report-token.yaml", files["05-report-token.yaml"], `{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "mitstack-report-token", "namespace": "mitstack-node"}, "stringData": {"token": "`+testutil.FixtureReportToken+`"}}`)
			sameJSON(t, "04-mitstack-node.yaml", files["04-mitstack-node.yaml"], `{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "mitstack-node", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}}`)
		}},
		refused(http.StatusNotFound), refused(http.StatusBadRequest), refused(http.StatusUnauthorized), refused(http.StatusForbidden),
		{name: "a 503, a 429 then a 200 retries and enrols", statuses: []int{503, 429, 200}, bound: enrolRetryBound, check: func(t *testing.T, o enrolOutcome) {
			testutil.FatalIf(t, o.run.Err != nil, "the enrol script gave up while the endpoint was busy: %v\n%s", o.run.Err, o.run.Output())
			n := len(o.srv.Received())
			testutil.FailIf(t, n != 3, "the enrol script sent %d requests over a 503, a 429 and a 200, want 3", n)
			assertSlept(t, o.sleeps, "1", "2")
			o.wrote(t, testutil.EnrolResponseBody)
		}},
		{name: "a 500 then a 200 enrols", statuses: []int{500, 200}, bound: enrolRetryBound, quiet: true, check: func(t *testing.T, o enrolOutcome) {
			testutil.FatalIf(t, o.run.Err != nil, "the enrol script failed after a 500: %v\n%s", o.run.Err, o.run.Output())
		}},
		{name: "repeated 503s give up within the bound", statuses: busy, bound: enrolRetryBound, quiet: true, check: func(t *testing.T, o enrolOutcome) {
			o.failed(t, "repeated 503s", -1)
			n := len(o.srv.Received())
			testutil.FailIf(t, n < 2, "the enrol script sent %d request(s) to a 503, want it retried", n)
			assertSlept(t, o.sleeps, backoff...)
		}},
		{name: "a connection failure gives up within the bound", bound: enrolRetryBound, check: func(t *testing.T, o enrolOutcome) {
			o.failed(t, "a connection failure", 0)
			assertSlept(t, o.sleeps, backoff...)
		}},
	}
	for _, body := range []struct{ name, text string }{
		{"a body that is not JSON", "enrolled\n"},
		{"a JSON body that is a list", "[]\n"},
		{"only the old repositoryReadKey", testutil.EnrolAnswer(t, map[string]any{"repositoryReadKey": "a deploy key", "reportToken": testutil.FixtureReportToken})},
	} {
		cases = append(cases, enrolCase{name: "a 200 with " + body.name + " fails and writes nothing", statuses: ok, prepare: okWith(body.text),
			check: func(t *testing.T, o enrolOutcome) { o.failed(t, "a 200 with "+body.name, 1) }})
	}
	for _, field := range []string{"repositoryToken", "repositoryTokenExpiresAt", "reportToken", "notificationToken"} {
		for _, kind := range []struct {
			name   string
			change func(a map[string]any)
		}{
			{"no " + field, func(a map[string]any) { delete(a, field) }},
			{"an empty " + field, func(a map[string]any) { a[field] = "" }},
			{"a non-string " + field, func(a map[string]any) { a[field] = 3600 }},
		} {
			answer := map[string]any{
				"repositoryToken": testutil.FixtureRepositoryToken, "repositoryTokenExpiresAt": testutil.FixtureRepositoryTokenExpiresAt,
				"reportToken": testutil.FixtureReportToken, "notificationToken": testutil.FixtureNotificationToken,
			}
			kind.change(answer)
			cases = append(cases, enrolCase{name: "a 200 with " + kind.name + " fails naming the field", statuses: ok, prepare: okWith(testutil.EnrolAnswer(t, answer)),
				check: func(t *testing.T, o enrolOutcome) {
					o.failed(t, "a 200 with "+kind.name, 1)
					testutil.FailIf(t, !strings.Contains(o.run.Stderr, field), "on a 200 with %s the enrol script's stderr does not name %s:\n%s", kind.name, field, o.run.Stderr)
				}})
		}
	}
	for _, c := range []struct {
		name, body string
		reason     bool
	}{
		{"a JSON error", `{"error":"` + githubRefusal + `"}` + "\n", true},
		{"a body that is not JSON", "<html>Failed Dependency</html>\n", false},
		{"JSON with no error", `{"message":"Failed Dependency"}` + "\n", false},
	} {
		cases = append(cases, enrolCase{name: "a 424 with " + c.name + " names the status and the platform's reason", statuses: []int{http.StatusFailedDependency},
			prepare: func(s *testutil.FakeEnrolment) { s.AnswerStatusWith(http.StatusFailedDependency, c.body) },
			check: func(t *testing.T, o enrolOutcome) {
				o.failed(t, "a 424 with "+c.name, 1)
				testutil.FailIf(t, !strings.Contains(o.run.Stderr, "HTTP 424"), "on a 424 with %s the enrol script's stderr does not name HTTP 424:\n%s", c.name, o.run.Stderr)
				testutil.FailIf(t, c.reason && !strings.Contains(o.run.Stderr, githubRefusal), "on a 424 with %s the stderr does not carry the platform's error %q:\n%s", c.name, githubRefusal, o.run.Stderr)
			}})
	}

	t.Parallel()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			script, env := renderedEnrolment(t)
			srv, url, ca := (*testutil.FakeEnrolment)(nil), closedEndpoint(t), ""
			if c.statuses != nil {
				srv = testutil.NewFakeEnrolment(t, testutil.FixtureEnrolmentToken, c.statuses...)
				url, ca = srv.Endpoint(), srv.CAFile
				if c.prepare != nil {
					c.prepare(srv)
				}
			} else {
				srv = &testutil.FakeEnrolment{}
			}
			rec, sleeps := newArgvRecorder(t), newSleepRecorder(t)
			bound := cmp.Or(c.bound, enrolRefusalBound)

			run := runEnrolScript(t, script.Content, env, url, ca, bound, withPATH(rec.path()), sleeps.option())

			if c.quiet {
				assertQuietRun(t, "the enrol script", run, rec, srv.Received())
			}
			c.check(t, enrolOutcome{run: run, srv: srv, sleeps: sleeps, script: script.Content})
		})
	}
}
