package cluster

// The in-cluster refresh trades the report token for repository tokens and patches only each Secret's password.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

type refreshRun struct {
	run        testutil.EnrolRun
	srv        *testutil.FakeEnrolment
	api        *fakeKubeAPI
	rec        *argvRecorder
	shims      string
	kubectlLog string
}

const (
	// patchClusterRepositoryEnv set to false leaves cluster-repository to External Secrets, as on mitstack's home cluster.
	patchClusterRepositoryEnv = "MITSTACK_PATCH_CLUSTER_REPOSITORY"
	kubeAPIEnv                = "MITSTACK_KUBE_API"
	kubeCAFileEnv             = "MITSTACK_KUBE_CA_FILE"
	kubeTokenFileEnv          = "MITSTACK_KUBE_TOKEN_FILE"

	argocdSecretsPath       = "/api/v1/namespaces/argocd/secrets/"
	mergePatchContentType   = "application/merge-patch+json"
	kubeServiceAccountToken = "sentinel-service-account-token-0009"
)

// runRefresh runs the image's mitstack-repo-token with token in its Secret mount and the API server answered by a fake.
func runRefresh(t *testing.T, token string, statuses []int, answer string, kubeOpts ...fakeKubeOption) refreshRun {
	t.Helper()
	return runRefreshWithEnv(t, nil, token, statuses, answer, kubeOpts...)
}

func runRefreshWithEnv(t *testing.T, extraEnv []string, token string, statuses []int, answer string, kubeOpts ...fakeKubeOption) refreshRun {
	t.Helper()
	r := refreshRun{srv: &testutil.FakeEnrolment{}, api: newFakeKubeAPI(t, kubeOpts...), rec: newArgvRecorder(t), shims: t.TempDir(),
		kubectlLog: filepath.Join(t.TempDir(), "kubectl.log")}
	url, ca := closedEndpoint(t), ""
	if statuses != nil {
		r.srv = newRefreshEndpoint(t, statuses...)
		url, ca = r.srv.RefreshURL(), r.srv.CAFile
		if answer != "" && statuses[0] == http.StatusOK {
			r.srv.AnswerOKWith(answer)
		} else if answer != "" {
			r.srv.AnswerStatusWith(statuses[0], answer)
		}
	}
	testutil.WriteIn(t, r.shims, "kubectl", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+testutil.ShellQuote(r.kubectlLog)+"\necho 'kubectl: the refresh holds no right kubectl can use' >&2\nexit 1\n", 0o755)
	env := append([]string{repoTokenURLEnv + "=" + url, tokenFileEnv + "=" + testutil.WriteIn(t, t.TempDir(), "token", token, 0o600),
		kubeAPIEnv + "=" + r.api.URL, kubeCAFileEnv + "=" + r.api.caFile,
		kubeTokenFileEnv + "=" + testutil.WriteIn(t, t.TempDir(), "sa-token", kubeServiceAccountToken, 0o600)}, extraEnv...)
	r.run = testutil.RunShFile(t, "repo-token", filepath.Join(nodeAgentDir(t), "mitstack-repo-token"), refreshRunBound, testutil.EnrolRun{Tmp: t.TempDir()}, env, ca,
		[]testutil.ScriptRunOption{withPATH(r.rec.path()), withPathPrefix(r.shims)})
	return r
}

// patches maps each Secret the API server accepted a patch of to the password that patch set, and fails on any other request.
func (r refreshRun) patches(t *testing.T) map[string]string {
	t.Helper()
	ran, err := os.ReadFile(r.kubectlLog)
	testutil.FailIf(t, err == nil, "the refresh ran kubectl %q, which reads a Secret before it patches it, and the refresh holds no get", ran)
	got := map[string]string{}
	for _, req := range r.api.received() {
		name, _ := strings.CutPrefix(req.Path, argocdSecretsPath)
		testutil.FatalIf(t, !req.isMergePatchOfNamedArgoCDSecret(), "the refresh sent %s %s with Content-Type %q to the API server; want only a PATCH of %s<name> with Content-Type %s",
			req.Method, req.Path, req.ContentType, argocdSecretsPath, mergePatchContentType)
		testutil.FailIf(t, req.Authorization != "Bearer "+kubeServiceAccountToken, "the patch of %s carried an Authorization header that is not Bearer and the service-account token (%d characters received)", name, len(req.Authorization))
		for _, line := range req.SecretOnCmdline {
			t.Errorf("a process command line carried the service-account token or the password while the patch of %s was open: %s", name, line)
		}
		var p map[string]map[string]string
		testutil.FatalIf(t, json.Unmarshal(req.Body, &p) != nil, "the refresh patched %s with a body that is not JSON: %s", name, req.Body)
		testutil.FatalIf(t, len(p) != 1 || len(p["stringData"]) != 1, "the refresh patched %s with %v, want stringData.password alone", name, p)
		if req.Status == http.StatusOK {
			got[name] = p["stringData"]["password"]
		}
	}
	return got
}

func (r refreshRun) refused(t *testing.T, why string, wantRequests int) {
	t.Helper()
	assertExitedNonZero(t, why, r.run)
	n := len(r.srv.Received())
	testutil.FailIf(t, n != wantRequests, "the refresh sent %d requests on %s, want %d", n, why, wantRequests)
	testutil.FailIf(t, len(r.api.received()) != 0, "the refresh sent %d requests to the API server despite %s", len(r.api.received()), why)
	testutil.FailIf(t, len(r.patches(t)) != 0, "the refresh patched %v despite %s", r.patches(t), why)
}

type kubeRequest struct {
	Method, Path, Authorization, ContentType string
	Body                                     []byte
	Status                                   int
	SecretOnCmdline                          []string // every process command line that carried the service-account token or the patched password, redacted
}

func (k kubeRequest) isMergePatchOfNamedArgoCDSecret() bool {
	name, ok := strings.CutPrefix(k.Path, argocdSecretsPath)
	return k.Method == http.MethodPatch && ok && name != "" && !strings.Contains(name, "/") && k.ContentType == mergePatchContentType
}

// fakeKubeAPI is an API server over TLS, under a CA of its own, that admits only a merge PATCH of a named Secret in argocd.
type fakeKubeAPI struct {
	*httptest.Server
	caFile   string
	statuses map[string]int

	mu       sync.Mutex
	requests []kubeRequest
}

type fakeKubeOption func(*fakeKubeAPI)

// kubeAnswering has the fake answer each patch of the Secret name with status in place of 200.
func kubeAnswering(name string, status int) fakeKubeOption {
	return func(f *fakeKubeAPI) { f.statuses[name] = status }
}

func newFakeKubeAPI(t *testing.T, opts ...fakeKubeOption) *fakeKubeAPI {
	t.Helper()
	f := &fakeKubeAPI{statuses: map[string]int{}}
	for _, opt := range opts {
		opt(f)
	}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedLoopbackCert(t)}}
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	f.caFile = testutil.WriteTemp(t, "kube-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})))
	out, err := exec.Command("curl", "-fsS", "--max-time", "10", "--cacert", f.caFile, f.Server.URL+"/preflight").CombinedOutput()
	testutil.FatalIf(t, err != nil, "curl cannot reach the fake API server over TLS with its CA, so no run below would reach it either: %v\n%s", err, out)
	return f
}

// selfSignedLoopbackCert differs from the platform fake's certificate, so only the API server's own CA file verifies the fake.
func selfSignedLoopbackCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.FatalIf(t, err != nil, "generating the fake API server's key: %v", err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake kubernetes API server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	testutil.FatalIf(t, err != nil, "signing the fake API server's certificate: %v", err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *fakeKubeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/preflight" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	req := kubeRequest{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"),
		Body: raw, SecretOnCmdline: f.secretsOnCmdlines(raw)}
	name, _ := strings.CutPrefix(r.URL.Path, argocdSecretsPath)
	f.mu.Lock()
	switch {
	case !req.isMergePatchOfNamedArgoCDSecret():
		req.Status = http.StatusForbidden
	case f.statuses[name] != 0:
		req.Status = f.statuses[name]
	default:
		req.Status = http.StatusOK
	}
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(req.Status)
	if req.Status == http.StatusOK {
		_, _ = w.Write([]byte(testutil.MustJSON(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name, "namespace": "argocd"}})))
		return
	}
	_, _ = w.Write([]byte(testutil.MustJSON(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": req.Status})))
}

func (f *fakeKubeAPI) secretsOnCmdlines(body []byte) []string {
	var patch struct {
		StringData struct {
			Password string `json:"password"`
		} `json:"stringData"`
	}
	secrets := []string{kubeServiceAccountToken}
	if json.Unmarshal(body, &patch) == nil && patch.StringData.Password != "" {
		secrets = append(secrets, patch.StringData.Password)
	}
	var lines []string
	for _, secret := range secrets {
		withSecret, _ := testutil.ScanCmdlines(secret, f.URL)
		lines = append(lines, withSecret...)
	}
	return lines
}

func (f *fakeKubeAPI) received() []kubeRequest {
	defer testutil.Lock(&f.mu)()
	return slices.Clone(f.requests)
}

func TestRepoTokenScript_Contract(t *testing.T) {
	script := testutil.TestRepoFile(t, "scripts/nodeagent/repo-token.sh")

	testutil.FailIf(t, !shebangRe.MatchString(testutil.FirstLine(script)), "repo-token.sh starts with %q, want a POSIX sh shebang", testutil.FirstLine(script))
	testutil.AssertNamesAll(t, "repo-token.sh", script, "https://api.mitstack.dev"+testutil.RefreshEndpointPath, repoTokenURLEnv, "/var/run/mitstack/token", tokenFileEnv,
		"appRepositories", "repoUrl", "app-repository-", patchClusterRepositoryEnv,
		"-X PATCH", argocdSecretsPath, mergePatchContentType, "https://kubernetes.default.svc", "/var/run/secrets/kubernetes.io/serviceaccount",
		kubeAPIEnv, kubeCAFileEnv, kubeTokenFileEnv)
	testutil.FailIf(t, strings.Contains(script, "cluster-enrolments"), "repo-token.sh names the enrolment endpoint, which only the enrol script and the report probe post to")
	assertTokenOffCurlLines(t, "repo-token.sh", script, "(token_file|repositoryToken)")
}

func TestRepoTokenScript_AgainstTheRefreshEndpoint(t *testing.T) {
	t.Parallel()
	t.Run("a 200 patches the new token into cluster-repository and puts no token on a command line", func(t *testing.T) {
		t.Parallel()
		r := runRefresh(t, testutil.FixtureReportToken, []int{200}, "")

		testutil.FatalIf(t, r.run.Err != nil, "the refresh failed on a 200: %v\n%s", r.run.Err, r.run.Output())
		reqs := r.srv.Received()
		testutil.FatalIf(t, len(reqs) != 1, "the refresh sent %d requests, want exactly one\n%s", len(reqs), r.run.Output())
		testutil.FailIf(t, reqs[0].Method != http.MethodPost || reqs[0].Path != testutil.RefreshEndpointPath, "the request was %s %s, want POST %s", reqs[0].Method, reqs[0].Path, testutil.RefreshEndpointPath)
		testutil.FailIf(t, reqs[0].Authorization != "Bearer "+testutil.FixtureReportToken, "the Authorization header is not Bearer and the mounted report token (%d characters received)", len(reqs[0].Authorization))
		want := map[string]string{"cluster-repository": refreshedRepositoryToken}
		testutil.FailIf(t, !reflect.DeepEqual(r.patches(t), want), "the refresh patched %v, want %v", r.patches(t), want)
		testutil.FailIf(t, len(r.api.received()) != 1, "the refresh sent %d requests to the API server, want the one PATCH of cluster-repository", len(r.api.received()))
		assertQuietRun(t, "the refresh", r.run, r.rec, reqs)
		testutil.FailIf(t, strings.Contains(r.rec.commandLines(t), kubeServiceAccountToken), "a command line the refresh ran carried the service-account token")
		assertNothingLeftHolding(t, "the refresh", r.run.Tmp, []string{kubeServiceAccountToken})
	})
	for _, status := range []int{http.StatusUnauthorized, http.StatusFailedDependency, http.StatusServiceUnavailable} {
		t.Run("a "+strconv.Itoa(status)+" makes one attempt and patches nothing", func(t *testing.T) {
			t.Parallel()
			runRefresh(t, testutil.FixtureReportToken, []int{status}, "").refused(t, "a "+strconv.Itoa(status), 1)
		})
	}
	t.Run("a connection failure patches nothing", func(t *testing.T) {
		t.Parallel()
		runRefresh(t, testutil.FixtureReportToken, nil, "").refused(t, "a connection failure", 0)
	})
	for _, body := range []struct{ name, text string }{
		{"a body that is not JSON", "refreshed\n"},
		{"no repositoryToken", testutil.EnrolAnswer(t, map[string]any{"repositoryTokenExpiresAt": refreshedExpiresAt})},
		{"an empty repositoryToken", refreshAnswer(t, "")},
		{"a non-string repositoryToken", testutil.EnrolAnswer(t, map[string]any{"repositoryToken": 42, "repositoryTokenExpiresAt": refreshedExpiresAt})},
	} {
		t.Run("a 200 with "+body.name+" patches nothing", func(t *testing.T) {
			t.Parallel()
			runRefresh(t, testutil.FixtureReportToken, []int{200}, body.text).refused(t, "a 200 with "+body.name, 1)
		})
	}
	for _, c := range []struct{ name, token string }{{"an empty report token", ""}, {"a report token of two lines", "a\nb"}} {
		t.Run("sends nothing with "+c.name, func(t *testing.T) {
			t.Parallel()
			runRefresh(t, c.token, []int{200}, "").refused(t, c.name, 0)
		})
	}
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusCreated, http.StatusInternalServerError} {
		t.Run("fails when the API server answers the patch of cluster-repository with "+strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			r := runRefresh(t, testutil.FixtureReportToken, []int{200}, "", kubeAnswering("cluster-repository", status))

			assertExitedNonZero(t, "a "+strconv.Itoa(status)+" to the patch of cluster-repository", r.run)
			testutil.FailIf(t, len(r.patches(t)) != 0, "the refresh counted %v as patched despite a %d", r.patches(t), status)
		})
	}
	t.Run("fails when the API server cannot be reached", func(t *testing.T) {
		t.Parallel()
		r := runRefreshWithEnv(t, []string{kubeAPIEnv + "=https://" + closedAddr(t)}, testutil.FixtureReportToken, []int{200}, "")

		assertExitedNonZero(t, "an unreachable API server", r.run)
	})
	t.Run("fails when the API server's certificate is not under the service-account CA", func(t *testing.T) {
		t.Parallel()
		other := newFakeKubeAPI(t)
		r := runRefreshWithEnv(t, []string{kubeCAFileEnv + "=" + other.caFile}, testutil.FixtureReportToken, []int{200}, "")

		assertExitedNonZero(t, "an API server certificate the CA file does not sign", r.run)
		testutil.FailIf(t, len(r.api.received()) != 0, "the refresh sent %d requests to an API server whose certificate it could not verify", len(r.api.received()))
	})
}

const appRepositoryTokenPrefix = "sentinel-app-repository-token-"

func appRepositoryEntry(app string) map[string]any {
	return map[string]any{"project": "app-" + app, "repoUrl": "https://github.com/acme/" + app, "repositoryToken": appRepositoryTokenPrefix + app}
}

func appRepositoryEntryWith(app, member string, value any) map[string]any {
	entry := appRepositoryEntry(app)
	if value == nil {
		delete(entry, member)
	} else {
		entry[member] = value
	}
	return entry
}

func answerWithApps(t *testing.T, apps any) string {
	t.Helper()
	return testutil.EnrolAnswer(t, map[string]any{
		"repositoryToken": refreshedRepositoryToken, "repositoryTokenExpiresAt": refreshedExpiresAt, "appRepositories": apps,
	})
}

func TestRepoTokenScript_PerAppRepositories(t *testing.T) {
	malformed := func(entry any) string { return answerWithApps(t, []any{appRepositoryEntry("good"), entry}) }
	listing := func(apps ...string) string {
		entries := []any{}
		for _, app := range apps {
			entries = append(entries, appRepositoryEntry(app))
		}
		return answerWithApps(t, entries)
	}
	cases := []struct {
		name    string
		answer  string
		status  int
		kube    []fakeKubeOption
		patched []string // apps whose Secret the run patches with the answer's token
		refused bool     // the run fails and patches nothing
		env     []string
	}{
		{name: "patches each listed app's Secret and cluster-repository", status: 200, answer: listing("shop", "blog"), patched: []string{"shop", "blog"}},
		{name: "patches only cluster-repository when the answer lists no apps", status: 200, answer: listing()},
		{name: "patches only cluster-repository when the answer has no appRepositories member", status: 200, answer: refreshAnswer(t, refreshedRepositoryToken)},
		{name: "patches the other apps and exits 0 when an app's Secret is not synced yet", status: 200, answer: listing("shop", "blog"), patched: []string{"blog"},
			kube: []fakeKubeOption{kubeAnswering("app-repository-shop", http.StatusNotFound)}},
		{name: "patches the other apps and exits 0 when an app's Role is not synced yet", status: 200, answer: listing("shop", "blog"), patched: []string{"shop"},
			kube: []fakeKubeOption{kubeAnswering("app-repository-blog", http.StatusForbidden)}},
		{name: "patches the other apps and exits 0 when the API server fails an app's patch", status: 200, answer: listing("shop", "blog"), patched: []string{"blog"},
			kube: []fakeKubeOption{kubeAnswering("app-repository-shop", http.StatusInternalServerError)}},
		{name: "leaves cluster-repository alone and patches each app's Secret when its credential comes from External Secrets", status: 200, answer: listing("shop", "blog"), patched: []string{"shop", "blog"},
			env: []string{patchClusterRepositoryEnv + "=false"}, kube: []fakeKubeOption{kubeAnswering("cluster-repository", http.StatusForbidden)}},
		{name: "patches nothing and exits 0 when its credential comes from External Secrets and the answer lists no apps", status: 200, answer: listing(),
			env: []string{patchClusterRepositoryEnv + "=false"}},
		{name: "refuses an appRepositories that is not a list", status: 200, refused: true, answer: answerWithApps(t, "shop")},
		{name: "refuses an entry without a repositoryToken", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repositoryToken", nil))},
		{name: "refuses an entry with an empty repositoryToken", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repositoryToken", ""))},
		{name: "refuses an entry with a non-string repositoryToken", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repositoryToken", 42))},
		{name: "refuses an entry without a project", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", nil))},
		{name: "refuses a project that does not start with app-", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "default"))},
		{name: "refuses a project with nothing after app-", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "app-"))},
		{name: "refuses a project with an uppercase letter", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "app-Shop"))},
		{name: "refuses a project that is not one DNS label", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "app-shop.evil"))},
		{name: "refuses a project that names a path", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "app-../../etc/x"))},
		{name: "refuses a project longer than a DNS label", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "project", "app-"+strings.Repeat("a", 64)))},
		{name: "refuses an entry without a repoUrl", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repoUrl", nil))},
		{name: "refuses a repoUrl that is not https", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repoUrl", "http://github.com/acme/bad"))},
		{name: "refuses a repoUrl that is an ssh address", status: 200, refused: true, answer: malformed(appRepositoryEntryWith("bad", "repoUrl", "git@github.com:acme/bad.git"))},
		{name: "refuses an entry that is not an object", status: 200, refused: true, answer: malformed("shop")},
		{name: "patches nothing on a 503 even when the body lists apps", status: 503, refused: true, answer: listing("blog")},
		{name: "patches nothing on a 401 even when the body lists apps", status: 401, refused: true, answer: listing("blog")},
	}

	t.Parallel()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := runRefreshWithEnv(t, c.env, testutil.FixtureReportToken, []int{c.status}, c.answer, c.kube...)

			if c.refused {
				r.refused(t, c.name, 1)
				return
			}
			testutil.FatalIf(t, r.run.Err != nil, "the refresh failed on %s: %v\n%s", c.name, r.run.Err, r.run.Output())
			want := map[string]string{"cluster-repository": refreshedRepositoryToken}
			if c.env != nil {
				want = map[string]string{}
			}
			for _, app := range c.patched {
				want["app-repository-"+app] = appRepositoryTokenPrefix + app
				testutil.FailIf(t, strings.Contains(r.rec.commandLines(t), appRepositoryTokenPrefix+app), "a command line carried the token of app %s", app)
			}
			testutil.FailIf(t, !reflect.DeepEqual(r.patches(t), want), "the refresh patched %v, want %v", r.patches(t), want)
			sent := map[string]int{}
			for _, req := range r.api.received() {
				sent[req.Path]++
			}
			for path, n := range sent {
				testutil.FailIf(t, n != 1, "the refresh sent %d requests to %s, want one PATCH", n, path)
			}
			testutil.FailIf(t, c.env != nil && sent[argocdSecretsPath+"cluster-repository"] != 0, "the refresh patched cluster-repository, which External Secrets writes")
		})
	}
}
