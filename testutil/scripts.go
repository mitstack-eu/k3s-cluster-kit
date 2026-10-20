package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func EnrolAnswer(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	FatalIf(t, err != nil, "encoding the enrolment answer: %v", err)
	return string(raw) + "\n"
}

func TokenAnswer(t *testing.T, token, reportToken string) string {
	t.Helper()
	return EnrolAnswer(t, map[string]any{
		"repositoryToken": token, "repositoryTokenExpiresAt": FixtureRepositoryTokenExpiresAt,
		"reportToken": reportToken, "notificationToken": FixtureNotificationToken,
	})
}

func WriteIn(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), mode)
	FatalIf(t, err != nil, "writing %s error = %v; want nil", name, err)
	return path
}

func WriteTemp(t *testing.T, name, content string) string {
	t.Helper()
	return WriteIn(t, t.TempDir(), name, content, 0o600)
}

func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type EnrolRun struct {
	Dir, Tmp, Manifests string
	HostTar             string
	Stdout, Stderr      string
	Err                 error
	elapsed             time.Duration
}

func (r EnrolRun) Output() string { return r.Stdout + r.Stderr }

type ScriptRunOption func(env []string) []string

func RunSh(t *testing.T, what, script string, bound time.Duration, run EnrolRun, env []string, caFile string, opts []ScriptRunOption) EnrolRun {
	t.Helper()
	for _, tool := range []string{"sh", "curl", "python3"} {
		_, err := exec.LookPath(tool)
		FatalIf(t, err != nil, "%s is not on PATH, and the node has it: %v", tool, err)
	}
	return RunShFile(t, what, WriteTemp(t, what+".sh", script), bound, run, env, caFile, opts)
}

// runShFile runs the script at path, so a script that finds its siblings by its own path finds them.
func RunShFile(t *testing.T, what, path string, bound time.Duration, run EnrolRun, env []string, caFile string, opts []ScriptRunOption) EnrolRun {
	t.Helper()
	return RunProgram(t, what, []string{"sh", path}, bound, run, env, caFile, opts)
}

func RunProgram(t *testing.T, what string, argv []string, bound time.Duration, run EnrolRun, env []string, caFile string, opts []ScriptRunOption) EnrolRun {
	t.Helper()
	env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + run.Tmp, "TMPDIR=" + run.Tmp}, env...)
	if caFile != "" {
		env = append(env, "CURL_CA_BUNDLE="+caFile, "SSL_CERT_FILE="+caFile)
	}
	for _, opt := range opts {
		env = opt(env)
	}
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	run.Err = cmd.Run()
	run.elapsed = time.Since(start)
	run.Stdout, run.Stderr = stdout.String(), stderr.String()
	FatalIf(t, ctx.Err() != nil, "the %s script did not finish within %s:\n%s", what, bound, run.Output())
	return run
}

func TestRepoFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	FatalIf(t, err != nil, "reading %s: %v", path, err)
	return string(raw)
}

type RecordedEnrolRequest struct {
	Method, Path, Authorization, ContentType string
	Body                                     []byte
	TokenOnCmdline                           []string // every process command line that carried the token, the token itself redacted
	SawClient                                bool     // whether any process command line carried this server's URL, which shows the scan could see the client at all
}

type FakeEnrolment struct {
	*httptest.Server
	CAFile   string
	token    string
	statuses []int

	mu       sync.Mutex
	okBody   string
	bodies   map[int]string
	requests []RecordedEnrolRequest
}

func NewFakeEnrolment(t *testing.T, token string, statuses ...int) *FakeEnrolment {
	t.Helper()
	FatalIf(t, len(statuses) == 0, "newFakeEnrolment needs at least one status to answer with")
	f := &FakeEnrolment{token: token, statuses: statuses, okBody: EnrolResponseBody}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	f.CAFile = WriteTemp(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})))
	pre := exec.Command("curl", "-fsS", "--max-time", "10", f.Server.URL+"/preflight")
	pre.Env = []string{"PATH=" + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + f.CAFile, "SSL_CERT_FILE=" + f.CAFile}
	out, err := pre.CombinedOutput()
	FatalIf(t, err != nil, "curl cannot reach the test enrolment server over TLS, so no run below would reach it either: %v\n%s", err, out)
	return f
}

func (f *FakeEnrolment) Endpoint() string { return f.Server.URL + EnrolEndpointPath }

func (f *FakeEnrolment) RefreshURL() string { return f.Server.URL + RefreshEndpointPath }

func (f *FakeEnrolment) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/preflight" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	withToken, sawClient := ScanCmdlines(f.token, f.Server.URL)
	f.mu.Lock()
	n := len(f.requests)
	f.requests = append(f.requests, RecordedEnrolRequest{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
		ContentType: r.Header.Get("Content-Type"), Body: raw, TokenOnCmdline: withToken, SawClient: sawClient})
	status := f.statuses[min(n, len(f.statuses)-1)]
	body, custom := f.bodies[status]
	okBody := f.okBody
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	switch {
	case status == http.StatusOK:
		_, _ = w.Write([]byte(okBody))
	case custom:
		_, _ = w.Write([]byte(body))
	default:
		_, _ = w.Write([]byte(`{"message":"` + http.StatusText(status) + `"}`))
	}
}

func (f *FakeEnrolment) AnswerStatusWith(status int, body string) {
	defer Lock(&f.mu)()
	if f.bodies == nil {
		f.bodies = map[int]string{}
	}
	f.bodies[status] = body
}

func (f *FakeEnrolment) AnswerOKWith(body string) {
	defer Lock(&f.mu)()
	f.okBody = body
}

func (f *FakeEnrolment) Received() []RecordedEnrolRequest {
	defer Lock(&f.mu)()
	return slices.Clone(f.requests)
}

func ScanCmdlines(token, url string) (withToken []string, sawURL bool) {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		line := strings.ReplaceAll(string(raw), "\x00", " ")
		if strings.Contains(line, token) {
			withToken = append(withToken, strings.ReplaceAll(line, token, "<token>"))
		}
		sawURL = sawURL || strings.Contains(line, url)
	}
	return withToken, sawURL
}

type FakeTool struct{ Path, runsFile string }

// toolAnswer answers the exact arguments args, or any arguments the shell pattern glob matches when glob is set.
type ToolAnswer struct {
	Args, Stdout, Stderr string
	Exit                 int
	Glob                 string
}

const FakeToolRunEnd = "--fake-tool-run-end--"

func NewFakeTool(t *testing.T, name, stdout, stderr string, exit int, answers ...ToolAnswer) FakeTool {
	t.Helper()
	dir := t.TempDir()
	f := FakeTool{Path: filepath.Join(dir, name), runsFile: filepath.Join(dir, "runs")}
	emit := func(key, stdout, stderr string, exit int) string {
		out := WriteIn(t, dir, key+".stdout", stdout, 0o600)
		errOut := WriteIn(t, dir, key+".stderr", stderr, 0o600)
		return "cat " + ShellQuote(out) + "; cat " + ShellQuote(errOut) + " >&2; exit " + strconv.Itoa(exit)
	}
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + ShellQuote(f.runsFile) + "; done\nprintf '%s\\n' " + ShellQuote(FakeToolRunEnd) + " >> " + ShellQuote(f.runsFile) + "\ncase \"$*\" in\n"
	for i, a := range answers {
		pattern := ShellQuote(a.Args)
		if a.Glob != "" {
			pattern = a.Glob
		}
		script += "  " + pattern + ") " + emit("answer-"+strconv.Itoa(i), a.Stdout, a.Stderr, a.Exit) + " ;;\n"
	}
	WriteIn(t, dir, name, script+"esac\n"+emit("canned", stdout, stderr, exit)+"\n", 0o755)
	return f
}

func (f FakeTool) Runs(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(f.runsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	FatalIf(t, err != nil, "reading the fake tool's runs: %v", err)
	var out [][]string
	run := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == FakeToolRunEnd {
			out, run = append(out, run), []string{}
			continue
		}
		run = append(run, line)
	}
	return out
}

func (f FakeTool) Ran(t *testing.T, want ...string) bool {
	t.Helper()
	return slices.ContainsFunc(f.Runs(t), func(args []string) bool { return slices.Equal(args, want) })
}

func Reply(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func Lock(mu *sync.Mutex) func() {
	mu.Lock()
	return mu.Unlock
}
