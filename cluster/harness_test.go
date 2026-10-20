package cluster

// harness_test.go holds the fakes, fixtures and parsers the package tests share.

import (
	"bytes"
	"cmp"
	"crypto/sha1"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

func stringsOf(t *testing.T, what string, v any) []string {
	t.Helper()
	items, ok := v.([]any)
	testutil.FatalIf(t, !ok, "%s is %T, want a list of strings", what, v)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		testutil.FatalIf(t, !ok, "%s holds %T, want strings", what, it)
		out = append(out, s)
	}
	return out
}

//go:embed testdata/fakes testdata/report testdata/k3s testdata/want testdata/patchcheck testdata/scan
var fixtureFS embed.FS

func testFile(name string) string {
	raw, err := fixtureFS.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func testLines(name string) []string {
	return strings.Split(strings.TrimSuffix(testFile(name), "\n"), "\n")
}

const (
	nodeScriptMetadataEnv = "MITSTACK_METADATA_URL"
	nodeScriptDropInEnv   = "MITSTACK_K3S_DROPIN_DIR"
	metadataPath          = "/hetzner/v1/metadata"
	dropInFile            = "10-hcloud-node.yaml"

	enrolScriptURLEnv      = "MITSTACK_ENROLMENT_URL"
	repoCredentialFile     = "05-cluster-repository.yaml"
	notificationSecretFile = "05-argocd-notifications-secret.yaml"
	enrolRefusalBound      = 60 * time.Second
	enrolRetryBound        = 120 * time.Second

	repoTokenURLEnv = "MITSTACK_REFRESH_URL"
	refreshRunBound = 30 * time.Second

	tokenFileEnv   = "MITSTACK_TOKEN_FILE"
	hostDirEnv     = "MITSTACK_HOST_DIR"
	bootIDPath     = "/proc/sys/kernel/random/boot_id"
	reportRunBound = 30 * time.Second

	reportOSReleaseEnv             = "MITSTACK_OS_RELEASE"
	reportUserDataURLEnv           = "MITSTACK_USERDATA_URL"
	reportUnattendedUpgradesLogEnv = "MITSTACK_UNATTENDED_UPGRADES_LOG"
	reportRebootRequiredEnv        = "MITSTACK_REBOOT_REQUIRED"
	reportSSEnv                    = "MITSTACK_SS"
	reportNftEnv                   = "MITSTACK_NFT"
	userDataPath                   = "/hetzner/v1/userdata"
	reuseResultFile                = "enrolment-reuse.json"
	patchCheckFile                 = "patch-check.json"

	metadataProbeNamespace   = "mitstack-metadata-probe"
	metadataProbeImage       = "quay.io/curl/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"
	metadataProbeUserDataURL = "http://" + metadataServiceAddress + userDataPath
	ciliumStatusCommand      = "cilium-dbg status"
	hubbleObserveCommand     = "hubble observe --last 20"

	cannedSSHUnits        = "masked\nmasked\n"
	cannedSSHUnitsExit    = 1
	autoUpgradeUnitsArgs  = "is-enabled " + autoUpgradeUnits
	cannedProbeCreatedAt  = "2026-10-04T09:50:01Z"
	cannedProbeStartedAt  = "2026-10-04T09:50:04Z"
	cannedProbeFinishedAt = "2026-10-04T09:50:14Z"

	demoSubscription  = "7b1e4c2a-9d3f-4e8b-a6c5-1f2e3d4c5b6a"
	subscriptionLabel = "mitstack.dev/subscription"

	repositoryTokenUsername  = "x-access-token"
	staleRepositoryToken     = "sentinel-stale-repository-token-0004"
	refreshedRepositoryToken = "sentinel-refreshed-repository-token-0005"
	refreshedExpiresAt       = "2026-10-01T11:14:03Z"
	clusterSecretSentinel    = "sentinel-served-cluster-secret-0004"
	githubRefusal            = "GitHub refused a read token for the cluster repository: 422 Resource not accessible by integration"
)

var (
	cannedJournal = testLines("report/journal.txt")
	cannedNodes   = testFile("k3s/nodes.json")
)

func withoutEnv(key string) testutil.ScriptRunOption {
	return func(env []string) []string {
		return slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, key+"=") })
	}
}

func withEnv(key, value string) testutil.ScriptRunOption {
	return func(env []string) []string { return append(withoutEnv(key)(env), key+"="+value) }
}

func withPATH(path string) testutil.ScriptRunOption { return withEnv("PATH", path) }

func withPathPrefix(dir string) testutil.ScriptRunOption {
	return func(env []string) []string {
		for _, kv := range env {
			if rest, ok := strings.CutPrefix(kv, "PATH="); ok {
				return withPATH(dir + string(os.PathListSeparator) + rest)(env)
			}
		}
		return withPATH(dir)(env)
	}
}

func runEnrolScript(t *testing.T, script, env, url, caFile string, bound time.Duration, opts ...testutil.ScriptRunOption) testutil.EnrolRun {
	t.Helper()
	run := testutil.EnrolRun{Dir: t.TempDir(), Tmp: t.TempDir(), Manifests: t.TempDir()}
	testutil.WriteIn(t, run.Dir, testutil.EnrolScriptEnvFile, env, 0o600)
	return testutil.RunSh(t, "enrol", script, bound, run, []string{enrolScriptURLEnv + "=" + url, testutil.EnrolScriptDirEnv + "=" + run.Dir, testutil.EnrolManifestsDirEnv + "=" + run.Manifests}, caFile, opts)
}

// nodeAgentDir lays out the image's scripts as the Dockerfile's COPY lines do.
func nodeAgentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, line := range strings.Split(testutil.TestRepoFile(t, "scripts/nodeagent/Dockerfile"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "COPY" {
			continue
		}
		if strings.HasPrefix(fields[1], "--chmod=") {
			fields = fields[1:]
		}
		sources, dest := fields[1:len(fields)-1], fields[len(fields)-1]
		for _, src := range sources {
			name := filepath.Base(dest)
			if strings.HasSuffix(dest, "/") {
				name = filepath.Base(src)
			}
			testutil.WriteIn(t, dir, name, testutil.TestRepoFile(t, src), 0o755)
		}
	}
	return dir
}

// fakeNsenter runs its command in the test's own namespaces once it is asked for all five of process 1's.
const fakeNsenter = `#!/bin/sh
case "$*" in
  "-t 1 -m -u -i -n -p -- "*) shift 8 ;;
  *) echo "nsenter: want -t 1 -m -u -i -n -p --, got $*" >&2; exit 1 ;;
esac
exec "$@"
`

// runReportScript runs mitstack-host and then mitstack-report, as the node-agent pod's two containers do.
func runReportScript(t *testing.T, dir, token, url, caFile, journalctl string, opts ...testutil.ScriptRunOption) testutil.EnrolRun {
	t.Helper()
	agent, hostDir, shims := nodeAgentDir(t), t.TempDir(), t.TempDir()
	testutil.WriteIn(t, shims, "nsenter", fakeNsenter, 0o755)
	testutil.WriteIn(t, shims, "kubectl", "#!/bin/sh\nexec \"$"+testutil.ReportK3sEnv+"\" kubectl \"$@\"\n", 0o755)
	tokenFile := testutil.WriteIn(t, t.TempDir(), "token", token, 0o600)
	env := append([]string{testutil.ReportScriptURLEnv + "=" + url, testutil.EnrolScriptDirEnv + "=" + dir, testutil.ReportJournalctlEnv + "=" + journalctl,
		hostDirEnv + "=" + hostDir, tokenFileEnv + "=" + tokenFile}, defaultEvidenceEnv(t)...)
	opts = append(opts, withPathPrefix(shims))
	tmp := t.TempDir()
	host := testutil.RunShFile(t, "host", filepath.Join(agent, "mitstack-host"), reportRunBound, testutil.EnrolRun{Dir: dir, Tmp: tmp}, env, caFile, opts)
	run := testutil.RunShFile(t, "report", filepath.Join(agent, "mitstack-report"), reportRunBound, testutil.EnrolRun{Dir: dir, Tmp: tmp}, env, caFile, opts)
	run.Stdout, run.Stderr, run.HostTar = host.Stdout+run.Stdout, host.Stderr+run.Stderr, filepath.Join(hostDir, "host.tar")
	if host.Err != nil {
		run.Err = host.Err
	}
	return run
}

func runNodeScript(t *testing.T, script string, md *fakeMetadata, bound time.Duration) (dropInDir string, run testutil.EnrolRun) {
	t.Helper()
	run = testutil.EnrolRun{Tmp: t.TempDir()}
	dropInDir = filepath.Join(run.Tmp, "etc", "rancher", "k3s", "config.yaml.d")
	return dropInDir, testutil.RunSh(t, "node", script, bound, run, []string{nodeScriptMetadataEnv + "=" + md.URL + metadataPath, nodeScriptDropInEnv + "=" + dropInDir}, "", nil)
}

// closedAddr holds a port on a socket that is bound and never listens until t ends, since a freed port can go to a parallel test's fake.
func closedAddr(t *testing.T) string {
	t.Helper()
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	testutil.FatalIf(t, err != nil, "opening the socket that holds a closed port error = %v; want nil", err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	testutil.FatalIf(t, err != nil, "binding the socket that holds a closed port error = %v; want nil", err)
	sa, err := syscall.Getsockname(fd)
	testutil.FatalIf(t, err != nil, "reading the held port error = %v; want nil", err)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
}

func closedEndpoint(t *testing.T) string {
	return "https://" + closedAddr(t) + testutil.EnrolEndpointPath
}

func renderedEnrolment(t *testing.T) (script testutil.CloudFile, env string) {
	t.Helper()
	_, cc := renderFixture(t)
	return cc.EnrolScript(t), cc.File(t, "/etc/mitstack/"+testutil.EnrolScriptEnvFile).Content
}

type sleepRecorder struct{ dir, log string }

func newSleepRecorder(t *testing.T) *sleepRecorder {
	t.Helper()
	r := &sleepRecorder{dir: t.TempDir(), log: filepath.Join(t.TempDir(), "sleep.log")}
	testutil.WriteIn(t, r.dir, "sleep", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+testutil.ShellQuote(r.log)+"\n", 0o755)
	return r
}

func (r *sleepRecorder) option() testutil.ScriptRunOption { return withPathPrefix(r.dir) }

func (r *sleepRecorder) delays(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(r.log)
	testutil.FatalIf(t, err != nil && !errors.Is(err, fs.ErrNotExist), "reading the recorded sleeps: %v", err)
	return strings.Fields(string(raw))
}

func assertSlept(t *testing.T, sleeps *sleepRecorder, want ...string) {
	t.Helper()
	got := sleeps.delays(t)
	testutil.FailIf(t, !slices.Equal(got, want), "the enrol script slept %v between attempts; want %v", got, want)
}

type argvRecorder struct{ dir, log string }

var recordedCommands = []string{
	"awk", "base64", "bash", "cat", "chmod", "cp", "curl", "cut", "dash", "date", "dd", "echo", "env", "grep", "head", "install", "jq", "mkdir",
	"mktemp", "mv", "printf", "python3", "rm", "sed", "sh", "tail", "tee", "touch", "tr", "xargs",
}

func newArgvRecorder(t *testing.T) *argvRecorder {
	t.Helper()
	r := &argvRecorder{dir: t.TempDir(), log: filepath.Join(t.TempDir(), "argv.log")}
	for _, name := range recordedCommands {
		if real, err := exec.LookPath(name); err == nil {
			testutil.WriteIn(t, r.dir, name, "#!/bin/sh\n{ printf '%s' "+testutil.ShellQuote(name)+"; for a in \"$@\"; do printf ' %s' \"$a\"; done; printf '\\n'; } >> "+testutil.ShellQuote(r.log)+"\nexec "+testutil.ShellQuote(real)+" \"$@\"\n", 0o755)
		}
	}
	return r
}

func (r *argvRecorder) path() string { return r.dir + string(os.PathListSeparator) + os.Getenv("PATH") }

func (r *argvRecorder) commandLines(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(r.log)
	testutil.FatalIf(t, err != nil && !errors.Is(err, fs.ErrNotExist), "reading the recorded command lines: %v", err)
	return string(raw)
}

func assertNothingLeftHolding(t *testing.T, who, dir string, fragments []string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		testutil.FailIf(t, readErr == nil && slices.ContainsFunc(fragments, func(f string) bool { return bytes.Contains(raw, []byte(f)) }), "%s left a secret behind in %s", who, path)
		return nil
	})
}

func enrolledDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	testutil.WriteIn(t, dir, testutil.EnrolScriptJSONFile, body, 0o600)
	return dir
}

func enrolledAnswer(t *testing.T) string {
	t.Helper()
	return testutil.TokenAnswer(t, testutil.FixtureRepositoryToken, testutil.FixtureReportToken)
}

func refreshAnswer(t *testing.T, token string) string {
	t.Helper()
	return testutil.EnrolAnswer(t, map[string]any{"repositoryToken": token, "repositoryTokenExpiresAt": refreshedExpiresAt})
}

func newRefreshEndpoint(t *testing.T, statuses ...int) *testutil.FakeEnrolment {
	t.Helper()
	srv := testutil.NewFakeEnrolment(t, testutil.FixtureReportToken, statuses...)
	srv.AnswerOKWith(refreshAnswer(t, refreshedRepositoryToken))
	return srv
}

type metadataAnswer struct {
	status, failFirst int
	body              string
}

type fakeMetadata struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func newFakeMetadata(t *testing.T, answers map[string]metadataAnswer) *fakeMetadata {
	t.Helper()
	md := &fakeMetadata{hits: map[string]int{}}
	md.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, known := answers[r.URL.Path]
		if !known || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		md.mu.Lock()
		md.hits[r.URL.Path]++
		n := md.hits[r.URL.Path]
		md.mu.Unlock()
		if n <= a.failFirst {
			http.Error(w, "metadata service not ready", http.StatusServiceUnavailable)
			return
		}
		testutil.Reply(w, cmp.Or(a.status, http.StatusOK), a.body)
	}))
	t.Cleanup(md.Server.Close)
	return md
}

func (md *fakeMetadata) hitCount(path string) int {
	defer testutil.Lock(&md.mu)()
	return md.hits[path]
}

func fakeUname(t *testing.T, kernel string) testutil.FakeTool {
	t.Helper()
	return testutil.NewFakeTool(t, "uname", "", "uname: this fake answers only -r and -n\n", 1, testutil.ToolAnswer{Args: "-r", Stdout: kernel + "\n"}, testutil.ToolAnswer{Args: "-n", Stdout: fixtureNodeName + "\n"})
}

var (
	hostNodeNameOnce sync.Once
	hostNodeNameVal  string
	hostNodeNameErr  error
)

func hostNodeName(t *testing.T) string {
	t.Helper()
	hostNodeNameOnce.Do(func() {
		out, err := exec.Command("uname", "-n").Output()
		hostNodeNameVal, hostNodeNameErr = strings.TrimSpace(string(out)), err
	})
	testutil.FatalIf(t, hostNodeNameErr != nil || hostNodeNameVal == "", "uname -n names no node here (%v), and the fake k3s serves the kubelet's configuration for it", hostNodeNameErr)
	return hostNodeNameVal
}

type fakeJournal struct{ path, argsFile string }

func newFakeJournal(t *testing.T, lines []string) fakeJournal {
	t.Helper()
	dir := t.TempDir()
	testutil.WriteIn(t, dir, "journal.txt", strings.Join(lines, "\n")+"\n", 0o600)
	testutil.WriteIn(t, dir, "journalctl", testFile("fakes/journalctl.sh"), 0o755)
	return fakeJournal{path: filepath.Join(dir, "journalctl"), argsFile: filepath.Join(dir, "args")}
}

func (j fakeJournal) args(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(j.argsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	testutil.FatalIf(t, err != nil, "reading the fake journalctl's arguments: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

type fakeCurl struct{ dir, log string }

func newFakeCurl(t *testing.T, body string) fakeCurl {
	t.Helper()
	python, err := exec.LookPath("python3")
	testutil.FatalIf(t, err != nil, "python3 is not on PATH, and the fake curl runs on it: %v", err)
	dir, work := t.TempDir(), t.TempDir()
	c := fakeCurl{dir: dir, log: filepath.Join(work, "curl.log")}
	program, bodyFile := testutil.WriteIn(t, work, "curl.py", testFile("fakes/curl.py"), 0o600), testutil.WriteIn(t, work, "body", body, 0o600)
	testutil.WriteIn(t, dir, "curl", "#!/bin/sh\nexec "+testutil.ShellQuote(python)+" "+testutil.ShellQuote(program)+" "+testutil.ShellQuote(c.log)+" "+testutil.ShellQuote(bodyFile)+" \"$@\"\n", 0o755)
	return c
}

const (
	argocdClusterIP = "10.43.77.20"
	argocdBaseURL   = "https://argocd-server.argocd.svc:443"
	argocdSentinel  = "argocd-answer-sentinel-7f3a"
)

// The order is the order the node asks the routes in.
var argocdRoutePaths = []string{
	"/api/v1/session/userinfo", "/api/v1/account", "/api/v1/applications", "/api/v1/applicationsets", "/api/v1/certificates",
	"/api/v1/clusters", "/api/v1/gpgkeys", "/api/v1/notifications/services", "/api/v1/notifications/templates",
	"/api/v1/notifications/triggers", "/api/v1/projects", "/api/v1/repocreds", "/api/v1/repositories", "/api/v1/settings",
	"/api/v1/settings/plugins", "/api/v1/write-repocreds", "/api/v1/write-repositories",
}

const argocdUserinfoPath = "/api/v1/session/userinfo"

type argocdAnswer struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Exit   int    `json:"exit"`
	Stderr string `json:"stderr"`
}

// cannedArgoCDAnswers is what an Argo CD that wants a session answers: userinfo 200 and settings 200, the rest 401.
// Every body carries the sentinel, which no report may repeat.
func cannedArgoCDAnswers() map[string]argocdAnswer {
	answers := map[string]argocdAnswer{}
	for _, path := range argocdRoutePaths {
		answers[path] = argocdAnswer{Status: 401, Body: `{"error":"no session information","code":16,"message":"` + argocdSentinel + path + `"}`}
	}
	answers[argocdUserinfoPath] = argocdAnswer{Status: 200, Body: `{"loggedIn":false,"iss":"` + argocdSentinel + `","username":"` + argocdSentinel + `"}`}
	answers["/api/v1/settings"] = argocdAnswer{Status: 200, Body: `{"url":"https://argocd.example.com","appLabelKey":"` + argocdSentinel + `"}`}
	return answers
}

// Every curl call that is not an Argo CD route runs the next curl on PATH.
func newFakeArgoCDCurl(t *testing.T, answers map[string]argocdAnswer) fakeCurl {
	t.Helper()
	return newFakeArgoCDCurlAt(t, argocdBaseURL, answers)
}

// newFakeArgoCDCurlAt answers at base, since the host report of 3.0.0 asked Argo CD at its cluster IP.
func newFakeArgoCDCurlAt(t *testing.T, base string, answers map[string]argocdAnswer) fakeCurl {
	t.Helper()
	python, err := exec.LookPath("python3")
	testutil.FatalIf(t, err != nil, "python3 is not on PATH, and the fake curl runs on it: %v", err)
	dir, work := t.TempDir(), t.TempDir()
	cfg, err := json.Marshal(map[string]any{"base": base, "routes": answers, "shimDir": dir})
	testutil.FatalIf(t, err != nil, "encoding the fake Argo CD curl's answers: %v", err)
	c := fakeCurl{dir: dir, log: filepath.Join(work, "curl.log")}
	program, config := testutil.WriteIn(t, work, "argocd-curl.py", testFile("fakes/argocd-curl.py"), 0o600), testutil.WriteIn(t, work, "routes.json", string(cfg), 0o600)
	testutil.WriteIn(t, dir, "curl", "#!/bin/sh\nexec "+testutil.ShellQuote(python)+" "+testutil.ShellQuote(program)+" "+testutil.ShellQuote(c.log)+" "+testutil.ShellQuote(config)+" \"$@\"\n", 0o755)
	return c
}

type curlAttempt struct {
	At   float64  `json:"at"`
	Argv []string `json:"argv"`
}

func (c fakeCurl) attempts(t *testing.T) []curlAttempt {
	t.Helper()
	raw, err := os.ReadFile(c.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	testutil.FatalIf(t, err != nil, "reading the fake curl's log: %v", err)
	var out []curlAttempt
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var a curlAttempt
		err := json.Unmarshal([]byte(line), &a)
		testutil.FatalIf(t, err != nil, "the fake curl's log line is not JSON: %v\n%s", err, line)
		out = append(out, a)
	}
	return out
}

type kubectlAnswer struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Exit   int    `json:"exit"`
}

type fakeK3sConfig struct {
	Answers        map[string]string        `json:"answers"`
	Raw            map[string]string        `json:"raw"`
	Label          kubectlAnswer            `json:"label"`
	Failures       map[string]kubectlAnswer `json:"failures"`
	Printing       map[string]string        `json:"printing"`
	SecretsEncrypt kubectlAnswer            `json:"secretsEncrypt"`
	Exec           map[string]kubectlAnswer `json:"exec"`
	Configz        string                   `json:"configz"`
	NodeName       string                   `json:"nodeName"`
	Probe          probePod                 `json:"probe"`
	Logs           map[string]string        `json:"logs"`
	Version        kubectlAnswer            `json:"version"`
	FirstCallDelay float64                  `json:"firstCallDelay"`
	Generate       map[string]generateSpec  `json:"generate"`
	Applies        map[string]kubectlAnswer `json:"applies"`
	SecretB64      string                   `json:"secretB64"`
	secret         string
}

type probePod struct {
	Phase      string `json:"phase"`
	Log        string `json:"log"`
	CreatedAt  string `json:"createdAt"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Image      string `json:"image"`
}

const (
	readNodes                 = "nodes"
	readArgoCDPods            = "argocdPods"
	readKubeSystem            = "kubeSystemPods"
	readJobs                  = "jobs"
	readHelmCharts            = "helmcharts"
	readApplications          = "applications"
	readSecrets               = "secrets"
	readArgoCDMetrics         = "argocdMetrics"
	readCiliumMetrics         = "ciliumMetrics"
	readLabel                 = "label"
	readConfigz               = "configz"
	readKuredLog              = "kuredLog"
	readKuredPreviousLog      = "kuredPreviousLog"
	readUpgradePlans          = "upgradePlans"
	readUpgradeJobs           = "upgradeJobs"
	readNamespaces            = "namespaces"
	readSubscriptionResources = "subscriptionResources"
	readJWKS                  = "jwks"
	readArgoCDServices        = "argocdServices"
	readArgoCDIngresses       = "argocdIngresses"
	readAdmissionFixtures     = "admissionFixtures"
	readDefaultDeny           = "defaultDenyPolicies"
	readCertificates          = "certificates"
	readChallenges            = "challenges"
	readAppProjects           = "appProjects"
	readProbePods             = "probePods"
	readCloudNativePG         = "cloudNativePG"

	argocdMetricsPath     = "/apis/metrics.k8s.io/v1beta1/namespaces/argocd/pods"
	kubeSystemMetricsPath = "/apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods"
	jwksPath              = "/openid/v1/jwks"
)

// generateSpec has the fake build count entries of kind far past what one report can carry; testdata/fakes/k3s.py says what each kind holds.
type generateSpec struct {
	Kind   string         `json:"kind"`
	Count  int            `json:"count"`
	Prefix string         `json:"prefix"`
	Labels map[string]any `json:"labels"`
}

type fakeK3sOption func(*fakeK3sConfig)

func k3sGenerate(read, kind string, count int, prefix string, labels map[string]any) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Generate[read] = generateSpec{kind, count, prefix, labels} }
}

func k3sFailing(read string, exit int, stderr string) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Failures[read] = kubectlAnswer{Stderr: stderr, Exit: exit} }
}

func k3sPrinting(read, stdout string) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Printing[read] = stdout }
}

func k3sAnswer(read, listJSON string) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Answers[read] = listJSON }
}

// k3sApplying sets what the dry-run apply of the fixture the ConfigMap holds under rule prints and exits with.
func k3sApplying(rule, stdout, stderr string, exit int) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Applies[rule] = kubectlAnswer{Stdout: stdout, Stderr: stderr, Exit: exit} }
}

// k3sFixtures replaces the data of the admission-fixtures ConfigMap the node reads.
func k3sFixtures(data map[string]string) fakeK3sOption {
	doc := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "admission-fixtures", "namespace": "mitstack-admission-probe"}}
	if data != nil {
		doc["data"] = data
	}
	return func(c *fakeK3sConfig) { c.Answers[readAdmissionFixtures] = testutil.MustJSON(doc) }
}

// k3sNodeFixtures gives mitstack-node an admission-fixtures ConfigMap, which a cluster has only once it is seeded.
func k3sNodeFixtures(data map[string]string) fakeK3sOption {
	doc := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "admission-fixtures", "namespace": "mitstack-node"}, "data": data}
	return func(c *fakeK3sConfig) { c.Answers["nodeAdmissionFixtures"] = testutil.MustJSON(doc) }
}

func k3sLabel(stdout, stderr string, exit int) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Label = kubectlAnswer{Stdout: stdout, Stderr: stderr, Exit: exit} }
}

func k3sSecretsEncrypt(stdout, stderr string, exit int) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.SecretsEncrypt = kubectlAnswer{Stdout: stdout, Stderr: stderr, Exit: exit} }
}

func k3sExec(command, stdout, stderr string, exit int) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Exec[command] = kubectlAnswer{Stdout: stdout, Stderr: stderr, Exit: exit} }
}

func k3sConfigz(raw string) fakeK3sOption { return func(c *fakeK3sConfig) { c.Configz = raw } }

func k3sMetadataProbe(phase, log string) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Probe.Phase, c.Probe.Log = phase, log }
}

func k3sLogs(read, log string) fakeK3sOption { return func(c *fakeK3sConfig) { c.Logs[read] = log } }

func k3sVersion(stdout, stderr string, exit int) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.Version = kubectlAnswer{Stdout: stdout, Stderr: stderr, Exit: exit} }
}

func k3sDelayingFirstCall(d time.Duration) fakeK3sOption {
	return func(c *fakeK3sConfig) { c.FirstCallDelay = d.Seconds() }
}

func k3sServingSecret(value string) fakeK3sOption { return func(c *fakeK3sConfig) { c.secret = value } }

type fakeK3s struct{ path, argsFile string }

func newFakeK3s(t *testing.T, opts ...fakeK3sOption) fakeK3s {
	t.Helper()
	python, err := exec.LookPath("python3")
	testutil.FatalIf(t, err != nil, "python3 is not on PATH, and the fake k3s runs on it: %v", err)
	answers := map[string]string{}
	for _, a := range []struct{ read, file string }{
		{readNodes, "nodes"}, {readArgoCDPods, "argocd-pods"}, {readKubeSystem, "kube-system-pods"}, {readJobs, "helm-jobs"}, {readHelmCharts, "helm-charts"},
		{readApplications, "applications"}, {readSecrets, "argocd-secrets"}, {readArgoCDMetrics, "argocd-metrics"}, {readCiliumMetrics, "kube-system-metrics"},
		{readUpgradePlans, "upgrade-plans"}, {readUpgradeJobs, "upgrade-jobs"}, {readNamespaces, "namespaces"}, {readSubscriptionResources, "subscription-objects"}, {readJWKS, "jwks"},
		{readArgoCDServices, "argocd-services"}, {readArgoCDIngresses, "argocd-ingresses"},
		{readAdmissionFixtures, "admission-fixtures"}, {readDefaultDeny, "default-deny-policies"},
		{readCertificates, "certificates"}, {readChallenges, "challenges"}, {readAppProjects, "app-projects"}, {readCloudNativePG, "cloudnative-pg"},
	} {
		answers[a.read] = testFile("k3s/" + a.file + ".json")
	}
	applies := map[string]kubectlAnswer{}
	testutil.FatalIf(t, json.Unmarshal([]byte(testFile("k3s/admission-applies.json")), &applies) != nil, "testdata/k3s/admission-applies.json is not JSON")
	cfg := &fakeK3sConfig{
		Answers:        answers,
		Logs:           map[string]string{readKuredLog: testFile("report/kured.log"), readKuredPreviousLog: testFile("report/kured-previous.log")},
		Version:        kubectlAnswer{Stdout: "k3s version v1.36.3+k3s1 (2d0f82fa)\ngo version go1.24.6\n"},
		Raw:            map[string]string{argocdMetricsPath: readArgoCDMetrics, kubeSystemMetricsPath: readCiliumMetrics, jwksPath: readJWKS},
		Label:          kubectlAnswer{Stdout: testFile("report/dry-run-stdout.txt"), Stderr: testFile("report/dry-run-stderr.txt")},
		Failures:       map[string]kubectlAnswer{},
		Generate:       map[string]generateSpec{},
		Applies:        applies,
		Printing:       map[string]string{},
		SecretsEncrypt: kubectlAnswer{Stdout: testFile("report/secrets-encrypt-status.txt")},
		Exec: map[string]kubectlAnswer{
			ciliumStatusCommand:  {Stdout: testFile("report/cilium-status.txt")},
			hubbleObserveCommand: {Stdout: testFile("report/hubble-observe.txt")},
		},
		Configz:  testFile("k3s/configz.json"),
		NodeName: hostNodeName(t),
		Probe:    probePod{Phase: "Failed", CreatedAt: cannedProbeCreatedAt, StartedAt: cannedProbeStartedAt, FinishedAt: cannedProbeFinishedAt, Image: metadataProbeImage},
		secret:   clusterSecretSentinel,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(cfg.secret))
	cfg.SecretB64 = encodedSecret
	for read, answer := range cfg.Answers {
		cfg.Answers[read] = strings.ReplaceAll(strings.ReplaceAll(answer, "@SECRET_B64@", encodedSecret), "@SECRET@", cfg.secret)
	}
	raw, err := json.Marshal(cfg)
	testutil.FatalIf(t, err != nil, "encoding the fake k3s's answers: %v", err)
	dir := t.TempDir()
	k := fakeK3s{path: filepath.Join(dir, "k3s"), argsFile: filepath.Join(dir, "args")}
	config, program := testutil.WriteIn(t, dir, "answers.json", string(raw), 0o600), testutil.WriteIn(t, dir, "k3s.py", testFile("fakes/k3s.py"), 0o600)
	// python3 runs by its absolute path, so a recorded PATH never sees it.
	testutil.WriteIn(t, dir, "k3s", "#!/bin/sh\nexec "+testutil.ShellQuote(python)+" "+testutil.ShellQuote(program)+" "+testutil.ShellQuote(config)+" "+testutil.ShellQuote(k.argsFile)+" \"$@\"\n", 0o755)
	return k
}

func (k fakeK3s) calls(t *testing.T) []string {
	t.Helper()
	return k.lines(t, "")
}

func (k fakeK3s) lines(t *testing.T, suffix string) []string {
	t.Helper()
	raw, err := os.ReadFile(k.argsFile + suffix)
	if os.IsNotExist(err) {
		return nil
	}
	testutil.FatalIf(t, err != nil, "reading the fake k3s's record: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func (k fakeK3s) argvs(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	for _, line := range k.lines(t, ".jsonl") {
		var argv []string
		err := json.Unmarshal([]byte(line), &argv)
		testutil.FatalIf(t, err != nil, "the fake k3s recorded arguments that are not a JSON list: %v\n%s", err, line)
		out = append(out, argv)
	}
	return out
}

func (k fakeK3s) callTimes(t *testing.T) []time.Time {
	t.Helper()
	var out []time.Time
	for _, line := range k.lines(t, ".times") {
		secs, err := strconv.ParseFloat(line, 64)
		testutil.FatalIf(t, err != nil, "the fake k3s recorded a call time that is not a number: %q", line)
		out = append(out, time.Unix(0, int64(secs*float64(time.Second))))
	}
	return out
}

// defaultEvidenceEnv holds a fresh patch check, so the collector runs none unless a test asks, and fakes for the tools it would run.
func defaultEvidenceEnv(t *testing.T) []string {
	t.Helper()
	return []string{
		reportOSReleaseEnv + "=" + testutil.WriteTemp(t, "os-release", testFile("report/os-release")),
		testutil.ReportCloudInitLogEnv + "=" + testutil.WriteTemp(t, "cloud-init-output.log", testFile("report/cloud-init-output.log")),
		testutil.ReportK3sEnv + "=" + newFakeK3s(t).path,
		reportUserDataURLEnv + "=" + closedHTTPURL(t),
		enrolScriptURLEnv + "=" + closedEndpoint(t),
		reportSSEnv + "=" + testutil.NewFakeTool(t, "ss", testFile("report/listeners.txt"), "", 0).Path,
		testutil.ReportSystemctlEnv + "=" + testutil.NewFakeTool(t, "systemctl", cannedSSHUnits, "", cannedSSHUnitsExit, testutil.ToolAnswer{Args: autoUpgradeUnitsArgs, Stdout: "enabled\nenabled\nenabled\n"}).Path,
		reportNftEnv + "=" + testutil.NewFakeTool(t, "nft", testFile("report/metadata-guard.txt"), "", 0).Path,
		testutil.ReportStateDirEnv + "=" + stateDirHolding(t, testFile("report/patch-check.json")),
		reportUnattendedUpgradesLogEnv + "=" + testutil.WriteTemp(t, "unattended-upgrades.log", testFile("report/unattended-upgrades.log")),
		reportRebootRequiredEnv + "=" + filepath.Join(t.TempDir(), "reboot-required"),
		reportSystemdRunEnv + "=" + testutil.NewFakeTool(t, "systemd-run", "", noScanUnit, 1).Path,
		patchCheckAptGetEnv + "=" + testutil.NewFakeTool(t, "apt-get", "", "", 0).Path,
		patchCheckChannelsURLEnv + "=" + closedHTTPURL(t),
		patchCheckReleasesURLEnv + "=" + closedHTTPURL(t),
	}
}

// noScanUnit is the default fake systemd-run's refusal, so no report test starts a scan on the machine running it.
const noScanUnit = "Failed to start transient service unit: the test starts no unit\n"

func closedHTTPURL(t *testing.T) string { return "http://" + closedAddr(t) + userDataPath }

func stateDirHolding(t *testing.T, check string) string {
	t.Helper()
	dir := t.TempDir()
	testutil.WriteIn(t, dir, patchCheckFile, check, 0o644)
	return dir
}

func rebootSentinel(t *testing.T, mtime time.Time, pkgs string) string {
	t.Helper()
	path := testutil.WriteIn(t, t.TempDir(), "reboot-required", "*** System restart required ***\n", 0o644)
	testutil.WriteIn(t, filepath.Dir(path), "reboot-required.pkgs", pkgs, 0o644)
	err := os.Chtimes(path, mtime, mtime)
	testutil.FatalIf(t, err != nil, "setting the sentinel's mtime: %v", err)
	return path
}

type reportRig struct {
	t        *testing.T
	token    string
	srv      *testutil.FakeEnrolment
	url      string // replaces the endpoint, with no CA, when set
	dir      string
	answer   string
	nodeEnv  bool
	dirFiles map[string]string
	journal  []string
	jctl     fakeJournal
	k3sOpts  []fakeK3sOption
	k3sPath  string
	k3s      fakeK3s
	tools    map[string]testutil.FakeTool
	userData *fakeMetadata
	probe    *testutil.FakeEnrolment
	rec      *argvRecorder
	argocd   map[string]argocdAnswer
	curl     fakeCurl
	env      []testutil.ScriptRunOption
	run      testutil.EnrolRun
	req      testutil.RecordedEnrolRequest
}

type reportOption func(*reportRig)

func newReportRig(t *testing.T, opts ...reportOption) *reportRig {
	t.Helper()
	r := &reportRig{t: t, token: testutil.FixtureReportToken, srv: testutil.NewFakeEnrolment(t, testutil.FixtureReportToken, http.StatusOK),
		answer: enrolledAnswer(t), journal: cannedJournal, tools: map[string]testutil.FakeTool{}, dirFiles: map[string]string{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

func withPlatform(statuses ...int) reportOption {
	return func(r *reportRig) { r.srv = testutil.NewFakeEnrolment(r.t, testutil.FixtureReportToken, statuses...) }
}
func unreachablePlatform() reportOption       { return func(r *reportRig) { r.url = closedEndpoint(r.t) } }
func withAnswer(body string) reportOption     { return func(r *reportRig) { r.answer = body } }
func withToken(token string) reportOption     { return func(r *reportRig) { r.token = token } }
func withEmptyDir() reportOption              { return func(r *reportRig) { r.dir = r.t.TempDir() } }
func onNode() reportOption                    { return func(r *reportRig) { r.nodeEnv = true } }
func recording() reportOption                 { return func(r *reportRig) { r.rec = newArgvRecorder(r.t) } }
func withJournal(lines []string) reportOption { return func(r *reportRig) { r.journal = lines } }
func withArgoCDAnswers(overrides map[string]argocdAnswer) reportOption {
	return func(r *reportRig) {
		if r.argocd == nil {
			r.argocd = cannedArgoCDAnswers()
		}
		maps.Copy(r.argocd, overrides)
	}
}
func withK3s(opts ...fakeK3sOption) reportOption {
	return func(r *reportRig) { r.k3sOpts = append(r.k3sOpts, opts...) }
}
func withMissingK3s() reportOption {
	return func(r *reportRig) { r.k3sPath = filepath.Join(r.t.TempDir(), "k3s") }
}
func withFailingK3s(stderr string) reportOption {
	return func(r *reportRig) { r.k3sPath = testutil.NewFakeTool(r.t, "k3s", "", stderr, 1).Path }
}
func withPrintingK3s(stdout string) reportOption {
	return func(r *reportRig) { r.k3sPath = testutil.NewFakeTool(r.t, "k3s", stdout, "", 0).Path }
}
func withEnvVar(key, value string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(key, value)) }
}
func withSource(key, name, content string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(key, testutil.WriteTemp(r.t, name, content))) }
}
func withStateDir(check string) reportOption {
	return func(r *reportRig) {
		r.env = append(r.env, withEnv(testutil.ReportStateDirEnv, stateDirHolding(r.t, check)))
	}
}
func withHourOldCheck() reportOption {
	return func(r *reportRig) {
		dir := stateDirHolding(r.t, testFile("report/patch-check.json"))
		old := time.Now().Add(-61 * time.Minute)
		testutil.FatalIf(r.t, os.Chtimes(filepath.Join(dir, patchCheckFile), old, old) != nil, "ageing the kept patch check")
		r.env = append(r.env, withEnv(testutil.ReportStateDirEnv, dir))
	}
}
func withRebootSentinel(mtime time.Time, pkgs string) reportOption {
	return func(r *reportRig) {
		r.env = append(r.env, withEnv(reportRebootRequiredEnv, rebootSentinel(r.t, mtime, pkgs)))
	}
}
func withTool(key, name, stdout, stderr string, exit int, answers ...testutil.ToolAnswer) reportOption {
	return func(r *reportRig) {
		r.tools[name] = testutil.NewFakeTool(r.t, name, stdout, stderr, exit, answers...)
		r.env = append(r.env, withEnv(key, r.tools[name].Path))
	}
}
func withMissingTool(key string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(key, filepath.Join(r.t.TempDir(), "missing"))) }
}

func withToolsFromPATH() reportOption {
	return func(r *reportRig) {
		dirs := []string{}
		for _, tool := range []struct {
			key, name, stdout string
			exit              int
		}{{reportSSEnv, "ss", testFile("report/listeners.txt"), 0}, {testutil.ReportSystemctlEnv, "systemctl", cannedSSHUnits, cannedSSHUnitsExit}, {reportNftEnv, "nft", testFile("report/metadata-guard.txt"), 0}} {
			r.tools[tool.name] = testutil.NewFakeTool(r.t, tool.name, tool.stdout, "", tool.exit)
			dirs = append(dirs, filepath.Dir(r.tools[tool.name].Path))
			r.env = append(r.env, withoutEnv(tool.key))
		}
		r.env = append(r.env, withPATH(strings.Join(append(dirs, os.Getenv("PATH")), string(os.PathListSeparator))))
	}
}
func withUserData(status int, body string) reportOption {
	return func(r *reportRig) {
		r.userData = newFakeMetadata(r.t, map[string]metadataAnswer{userDataPath: {status: status, body: body}})
		r.env = append(r.env, withEnv(reportUserDataURLEnv, r.userData.URL+userDataPath))
	}
}
func withUnreachableUserData() reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(reportUserDataURLEnv, closedHTTPURL(r.t))) }
}

func withProbe(token string, statuses ...int) reportOption {
	return func(r *reportRig) {
		url := closedEndpoint(r.t)
		if statuses != nil {
			r.probe = testutil.NewFakeEnrolment(r.t, token, statuses...)
			url = r.probe.Endpoint()
		}
		r.env = append(r.env, withEnv(enrolScriptURLEnv, url))
	}
}

func (r *reportRig) exec() testutil.EnrolRun {
	t := r.t
	t.Helper()
	if r.dir == "" {
		r.dir = enrolledDir(t, r.answer)
		if r.nodeEnv {
			_, env := renderedEnrolment(t)
			testutil.WriteIn(t, r.dir, testutil.EnrolScriptEnvFile, env, 0o600)
		}
		for name, content := range r.dirFiles {
			testutil.WriteIn(t, r.dir, name, content, 0o600)
		}
	}
	if r.jctl.path == "" {
		r.jctl = newFakeJournal(t, r.journal)
	}
	k3sPath := r.k3sPath
	if k3sPath == "" {
		if r.k3s.path == "" {
			r.k3s = newFakeK3s(t, r.k3sOpts...)
		}
		k3sPath = r.k3s.path
	}
	url, ca := r.srv.URL+testutil.ReportEndpointPath, r.srv.CAFile
	if r.url != "" {
		url, ca = r.url, ""
	}
	opts := append([]testutil.ScriptRunOption{withEnv(testutil.ReportK3sEnv, k3sPath)}, r.env...)
	if r.rec != nil {
		opts = append(opts, withPATH(r.rec.path()))
	}
	if r.curl.dir == "" {
		if r.argocd == nil {
			r.argocd = cannedArgoCDAnswers()
		}
		r.curl = newFakeArgoCDCurl(t, r.argocd)
	}
	opts = append(opts, withPathPrefix(r.curl.dir))
	r.run = runReportScript(t, r.dir, r.token, url, ca, r.jctl.path, opts...)
	return r.run
}

func (r *reportRig) send() *reportRig {
	t := r.t
	t.Helper()
	before := len(r.srv.Received())
	if r.exec(); r.run.Err != nil {
		t.Fatalf("the report script failed: %v\n%s", r.run.Err, testutil.Truncate(r.run.Output(), 2000))
	}
	reqs := r.srv.Received()
	n := len(reqs) - before
	testutil.FatalIf(t, n != 1, "the report script sent %d reports, want exactly one\n%s", n, testutil.Truncate(r.run.Output(), 2000))
	r.req = reqs[len(reqs)-1]
	return r
}

func (r *reportRig) fields() map[string]json.RawMessage { return reportFields(r.t, r.req) }

const (
	patchCheckAptGetEnv      = "MITSTACK_APT_GET"
	patchCheckUnameEnv       = "MITSTACK_UNAME"
	patchCheckBootDirEnv     = "MITSTACK_BOOT_DIR"
	patchCheckNowEnv         = "MITSTACK_NOW"
	patchCheckChannelsURLEnv = "MITSTACK_K3S_CHANNELS_URL"
	patchCheckReleasesURLEnv = "MITSTACK_K3S_RELEASES_URL"
	patchCheckUpdateStampEnv = "MITSTACK_APT_UPDATE_STAMP"
	aptUpdateStampDefault    = "/var/lib/apt/periodic/update-success-stamp"

	k3sChannelsPath = "/v1-release/channels"
	k3sReleasesPath = "/repos/k3s-io/k3s/releases"

	patchCheckMaxBehindDays = 14
	pendingUpgradesLimit    = 2048
	patchCheckRunBound      = 30 * time.Second
	defaultStampAge         = 6 * time.Hour

	fixtureNodeName = "orbitdemo-abcd2345"
	runningKernel   = "6.8.0-71-generic"
	runningOS       = "Ubuntu 24.04.3 LTS, kernel " + runningKernel
)

func k3sRelease(tag string, prerelease bool, published string) map[string]any {
	return map[string]any{"tag_name": tag, "name": tag, "draft": false, "prerelease": prerelease, "created_at": published, "published_at": published,
		"html_url": "https://github.com/k3s-io/k3s/releases/tag/" + tag}
}

var cannedK3sReleases = testutil.MustJSON([]any{
	k3sRelease("v1.36.6-rc1+k3s1", true, "2026-10-05T20:11:09Z"), k3sRelease("v1.37.1+k3s1", false, "2026-10-01T18:02:33Z"),
	k3sRelease("v1.36.5+k3s1", false, "2026-09-30T01:12:40Z"), k3sRelease("v1.35.9+k3s1", false, "2026-09-29T22:40:05Z"),
	k3sRelease("v1.36.5-rc1+k3s1", true, "2026-09-24T17:30:51Z"), k3sRelease("v1.37.0+k3s1", false, "2026-09-02T16:11:48Z"),
	k3sRelease("v1.36.4+k3s1", false, "2026-08-27T15:53:55Z"), k3sRelease("v1.36.4-rc1+k3s1", true, "2026-08-21T19:05:22Z"),
	k3sRelease("v1.36.3+k3s1", false, "2026-08-04T19:20:11Z"),
})

var (
	aptSimulationHeader     = testFile("patchcheck/apt-header.txt")
	cannedAptNothingPending = aptSimulationHeader + "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
	cannedAptPending        = testFile("patchcheck/apt-pending.txt")
	cannedK3sChannels       = testFile("patchcheck/k3s-channels.json")
)

func nodesRunning(version string) string {
	return strings.Replace(cannedNodes, `"kubeletVersion": "v1.36.3+k3s1"`, `"kubeletVersion": "`+version+`"`, 1)
}

type httpAnswer struct {
	status int
	body   string
}

type fakeK3sFeeds struct {
	*httptest.Server
	caFile string

	mu      sync.Mutex
	answers map[string]httpAnswer
	queries map[string][]string
}

func newFakeK3sFeeds(t *testing.T) *fakeK3sFeeds {
	t.Helper()
	f := &fakeK3sFeeds{answers: map[string]httpAnswer{k3sChannelsPath: {http.StatusOK, cannedK3sChannels}, k3sReleasesPath: {http.StatusOK, cannedK3sReleases}}, queries: map[string][]string{}}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	f.caFile = testutil.WriteTemp(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})))
	return f
}

func (f *fakeK3sFeeds) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	a, ok := f.answers[r.URL.Path]
	f.queries[r.URL.Path] = append(f.queries[r.URL.Path], r.URL.RawQuery)
	f.mu.Unlock()
	if !ok || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	testutil.Reply(w, a.status, a.body)
}

func (f *fakeK3sFeeds) answer(path string, status int, body string) {
	defer testutil.Lock(&f.mu)()
	f.answers[path] = httpAnswer{status, body}
}

func (f *fakeK3sFeeds) requests(path string) int {
	defer testutil.Lock(&f.mu)()
	return len(f.queries[path])
}

func (f *fakeK3sFeeds) channelsURL() string { return f.URL + k3sChannelsPath }

func (f *fakeK3sFeeds) releasesURL() string { return f.URL + k3sReleasesPath + "?per_page=100" }

func bootDirWith(t *testing.T, link string, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		testutil.WriteIn(t, dir, name, "kernel image "+name+"\n", 0o600)
	}
	if link != "" {
		for _, l := range []string{"vmlinuz", "vmlinuz.old"} {
			err := os.Symlink(link, filepath.Join(dir, l))
			testutil.FatalIf(t, err != nil, "linking /boot/%s: %v", l, err)
		}
	}
	return dir
}

type patchCheckNode struct {
	k3s            string
	aptGet         testutil.FakeTool
	uname          string
	osRelease      string
	bootDir        string
	stateDir       string
	rebootRequired string
	feeds          *fakeK3sFeeds
	updateStamp    string // apt's update-success-stamp, which each run touches stampAge before the clock, unless noStamp removes it
	stampAge       time.Duration
	noStamp        bool
}

func newPatchCheckNode(t *testing.T) *patchCheckNode {
	t.Helper()
	return &patchCheckNode{
		k3s:            newFakeK3s(t, k3sAnswer(readNodes, nodesRunning("v1.36.5+k3s1"))).path,
		aptGet:         testutil.NewFakeTool(t, "apt-get", cannedAptNothingPending, "", 0),
		uname:          fakeUname(t, runningKernel).Path,
		osRelease:      testutil.WriteTemp(t, "os-release", testFile("report/os-release")),
		bootDir:        bootDirWith(t, "vmlinuz-"+runningKernel, "vmlinuz-"+runningKernel),
		stateDir:       t.TempDir(),
		rebootRequired: filepath.Join(t.TempDir(), "reboot-required"),
		feeds:          newFakeK3sFeeds(t),
		updateStamp:    filepath.Join(t.TempDir(), "update-success-stamp"),
		stampAge:       defaultStampAge,
	}
}

func parseClock(t *testing.T, now string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, now)
	testutil.FatalIf(t, err != nil, "the clock %q is not RFC 3339: %v", now, err)
	return at
}

func (n *patchCheckNode) refreshedAt(t *testing.T, now string) string {
	t.Helper()
	return parseClock(t, now).Add(-n.stampAge).UTC().Format("2006-01-02T15:04:05Z")
}

func (n *patchCheckNode) touchStamp(t *testing.T, now string) {
	t.Helper()
	if n.noStamp {
		err := os.Remove(n.updateStamp)
		testutil.FatalIf(t, err != nil && !errors.Is(err, os.ErrNotExist), "removing the update stamp: %v", err)
		return
	}
	clock := time.Now()
	if now != "" {
		clock = parseClock(t, now)
	}
	testutil.WriteIn(t, filepath.Dir(n.updateStamp), filepath.Base(n.updateStamp), "", 0o644)
	at := clock.Add(-n.stampAge)
	testutil.FatalIf(t, os.Chtimes(n.updateStamp, at, at) != nil, "setting the update stamp's mtime")
}

func (n *patchCheckNode) running(t *testing.T, version string) {
	t.Helper()
	n.k3s = newFakeK3s(t, k3sAnswer(readNodes, nodesRunning(version))).path
}

type patchCheckRun struct {
	stdout, stderr string
	exit           int
	raw            []byte
	result         map[string]any
}

func (r patchCheckRun) output() string { return r.stdout + r.stderr }

func (r patchCheckRun) part(t *testing.T, name string) map[string]any {
	t.Helper()
	p, ok := r.result[name].(map[string]any)
	testutil.FatalIf(t, !ok, "%s.%s is %#v, want an object:\n%s", patchCheckFile, name, r.result[name], r.raw)
	return p
}

func (n *patchCheckNode) run(t *testing.T, now string, opts ...testutil.ScriptRunOption) patchCheckRun {
	t.Helper()
	n.touchStamp(t, now)
	env := []string{
		"CURL_CA_BUNDLE=" + n.feeds.caFile, "SSL_CERT_FILE=" + n.feeds.caFile, testutil.ReportK3sEnv + "=" + n.k3s, patchCheckAptGetEnv + "=" + n.aptGet.Path,
		patchCheckUnameEnv + "=" + n.uname, reportOSReleaseEnv + "=" + n.osRelease, patchCheckBootDirEnv + "=" + n.bootDir, testutil.ReportStateDirEnv + "=" + n.stateDir,
		reportRebootRequiredEnv + "=" + n.rebootRequired, patchCheckChannelsURLEnv + "=" + n.feeds.channelsURL(), patchCheckReleasesURLEnv + "=" + n.feeds.releasesURL(),
		patchCheckUpdateStampEnv + "=" + n.updateStamp,
	}
	if now != "" {
		env = append(env, patchCheckNowEnv+"="+now)
	}
	res := testutil.RunSh(t, "patch-check", testutil.TestRepoFile(t, "scripts/mitstack-patch-check.sh"), patchCheckRunBound, testutil.EnrolRun{Tmp: t.TempDir()}, env, "", opts)
	run := patchCheckRun{stdout: res.Stdout, stderr: res.Stderr}
	var exitErr *exec.ExitError
	switch {
	case res.Err == nil:
	case errors.As(res.Err, &exitErr):
		run.exit = exitErr.ExitCode()
	default:
		t.Fatalf("running the patch check: %v\n%s", res.Err, run.output())
	}
	raw, readErr := os.ReadFile(filepath.Join(n.stateDir, patchCheckFile))
	testutil.FatalIf(t, readErr != nil, "the patch check wrote no %s (exit %d): %v\n%s", patchCheckFile, run.exit, readErr, run.output())
	run.raw = raw
	err := json.Unmarshal(raw, &run.result)
	testutil.FatalIf(t, err != nil || run.result == nil, "%s is not a JSON object: %v\n%s", patchCheckFile, err, raw)
	return run
}

func renderOK(t *testing.T, in UserDataInputs) string {
	t.Helper()
	ud, err := RenderUserData(in)
	testutil.FatalIf(t, err != nil, "RenderUserData error = %v; want nil", err)
	return ud
}

func renderCC(t *testing.T, in UserDataInputs) (string, testutil.CloudConfig) {
	t.Helper()
	ud := renderOK(t, in)
	return ud, testutil.ParseUserData(t, ud)
}

const (
	// wantClusterBasesTag is the mitstack-eu/cluster-bases release the seed copies its components from.
	wantClusterBasesTag = "v0.5.0"
)

var imageByDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// gitTreeID is the object id git gives a directory of regular files with these names and contents.
func gitTreeID(files map[string]string) string {
	var tree bytes.Buffer
	for _, name := range slices.Sorted(maps.Keys(files)) {
		blob := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(files[name]), files[name])))
		tree.WriteString("100644 " + name + "\x00")
		tree.Write(blob[:])
	}
	sum := sha1.Sum(append([]byte(fmt.Sprintf("tree %d\x00", tree.Len())), tree.Bytes()...))
	return hex.EncodeToString(sum[:])
}
