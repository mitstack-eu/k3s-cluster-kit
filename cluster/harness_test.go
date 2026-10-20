package cluster

// harness_test.go holds the fakes, fixtures and parsers the package tests share.

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
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

	"go.yaml.in/yaml/v3"
)

const (
	// Every character of the first eight is in the base32 alphabet, so a
	// bucket name derived from the id could contain them.
	fixtureSubID    = "abcd2345-6f7a-4b2c-9d3e-5f6a7b2c3d4e"
	fixtureAppName  = "orbitdemo"
	fixtureOwner    = "acme"
	fixtureRepoName = fixtureAppName + "-cluster"
	fixtureRepo     = fixtureOwner + "/" + fixtureRepoName
	fixtureRepoURL  = "https://github.com/" + fixtureRepo
	otherAppName    = "otherapp"

	fixtureBucket         = "mitstack-oidc-abcdefghijklmnopqrstuvwxyz"
	fixtureEnrolmentToken = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
)

func issuerURLFor(bucket, subID string) string {
	return "https://" + bucket + ".s3.eu-central-1.amazonaws.com/" + subID
}

var wantSeedPaths = []string{
	"cluster-bases/cloudnative-pg/cloudnative-pg.yaml", "cluster-bases/cloudnative-pg/namespace.yaml",
	"cluster/admission-policy-mitstack-disallow-host-path.yaml",
	"cluster/admission-policy-mitstack-generate-default-deny.yaml",
	"cluster/admission-policy-mitstack-require-app-label.yaml",
	"cluster/admission-policy-mitstack-require-image-digest.yaml",
	"cluster/admission-policy-mitstack-require-resource-limits.yaml",
	"cluster/admission-policy-mitstack-restrict-image-registries.yaml",
	"cluster/admission-policy-mitstack-verify-node-agent-signature.yaml",
	"cluster/admission-probe-fixtures.yaml", "cluster/admission-probe-namespace.yaml",
	"cluster/argocd-notifications.yaml",
	"cluster/argocd.yaml", "cluster/cert-manager.yaml", "cluster/cilium.yaml", "cluster/cloudnative-pg.yaml", "cluster/cluster-issuer.yaml",
	"cluster/k3s-upgrade-plan.yaml", "cluster/kured.yaml", "cluster/kyverno.yaml", "cluster/network-policy-mitstack-database-slices.yaml",
	"cluster/node-agent-admission-fixtures.yaml", "cluster/node-agent.yaml", "cluster/repository-credentials.yaml", "cluster/system-upgrade-controller.yaml",
	"cluster/traefik.yaml", "repository-credentials/README.md",
}

type cloudFile struct {
	Path        string `yaml:"path"`
	Content     string `yaml:"content"`
	Permissions string `yaml:"permissions"`
	Owner       string `yaml:"owner"`
	Encoding    string `yaml:"encoding"`
	Defer       bool   `yaml:"defer"`
}

type cloudConfig struct {
	WriteFiles []cloudFile `yaml:"write_files"`
	RunCmd     []any       `yaml:"runcmd"`
}

func parseUserData(t *testing.T, userData string) cloudConfig {
	t.Helper()
	fatalIf(t, !strings.HasPrefix(userData, "#cloud-config\n"), "the user data must start with a #cloud-config line, starts with %q", firstLine(userData))
	var cc cloudConfig
	err := yaml.Unmarshal([]byte(userData), &cc)
	fatalIf(t, err != nil, "the user data is not valid YAML: %v", err)
	for i := range cc.WriteFiles {
		cc.WriteFiles[i].Content = decodeContent(t, cc.WriteFiles[i])
	}
	return cc
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func decodeContent(t *testing.T, f cloudFile) string {
	t.Helper()
	unbase64 := func() []byte {
		clean := strings.Join(strings.Fields(f.Content), "")
		raw, err := base64.StdEncoding.DecodeString(clean)
		fatalIf(t, err != nil, "%s: content declared %q is not base64: %v", f.Path, f.Encoding, err)
		return raw
	}
	switch strings.ToLower(f.Encoding) {
	case "", "text/plain":
		return f.Content
	case "b64", "base64":
		return string(unbase64())
	case "gz+b64", "gz+base64", "gzip+b64", "gzip+base64":
		zr, err := gzip.NewReader(bytes.NewReader(unbase64()))
		fatalIf(t, err != nil, "%s: content declared %q is not gzip: %v", f.Path, f.Encoding, err)
		raw, err := io.ReadAll(zr)
		fatalIf(t, err != nil, "%s: reading gzip content: %v", f.Path, err)
		return string(raw)
	default:
		t.Fatalf("%s: unsupported write_files encoding %q", f.Path, f.Encoding)
		return ""
	}
}

func (cc cloudConfig) file(t *testing.T, path string) cloudFile {
	t.Helper()
	var found []cloudFile
	for _, f := range cc.WriteFiles {
		if f.Path == path {
			found = append(found, f)
		}
	}
	fatalIf(t, len(found) != 1, "want exactly one write_files entry at %s, found %d", path, len(found))
	return found[0]
}

func (cc cloudConfig) onlyFileWhere(t *testing.T, what string, match func(cloudFile) bool) cloudFile {
	t.Helper()
	var found []cloudFile
	for _, f := range cc.WriteFiles {
		if match(f) {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		paths := make([]string, 0, len(found))
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		t.Fatalf("want exactly one write_files entry that is %s, found %d: %v", what, len(found), paths)
	}
	return found[0]
}

func (cc cloudConfig) nodeScript(t *testing.T) cloudFile {
	t.Helper()
	return cc.onlyFileWhere(t, "the node script (reads hetzner/v1/metadata)", func(f cloudFile) bool {
		return strings.Contains(f.Content, "hetzner/v1/metadata")
	})
}

func (cc cloudConfig) installer(t *testing.T) cloudFile {
	t.Helper()
	return cc.onlyFileWhere(t, "the verified installer (downloads k3s-io/k3s install.sh)", func(f cloudFile) bool {
		return strings.Contains(f.Content, "raw.githubusercontent.com/k3s-io/k3s/")
	})
}

func (cc cloudConfig) enrolScript(t *testing.T) cloudFile {
	t.Helper()
	// The report script names cluster-enrolments too, for its one-time reuse
	// probe, so the enrol script is the one that does not post reports.
	return cc.onlyFileWhere(t, "the enrol script (posts to cluster-enrolments)", func(f cloudFile) bool {
		return strings.Contains(f.Content, "cluster-enrolments") && !strings.Contains(f.Content, "cluster-reports")
	})
}

func (cc cloudConfig) runcmdText() string {
	var lines []string
	for _, entry := range cc.RunCmd {
		switch v := entry.(type) {
		case string:
			lines = append(lines, v)
		case []any:
			parts := make([]string, 0, len(v))
			for _, p := range v {
				parts = append(parts, fmt.Sprint(p))
			}
			lines = append(lines, strings.Join(parts, " "))
		default:
			lines = append(lines, fmt.Sprint(v))
		}
	}
	return strings.Join(lines, "\n")
}

func yamlDocs(t *testing.T, what, content string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(content))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		fatalIf(t, err != nil, "%s is not valid YAML: %v", what, err)
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

func yamlMap(t *testing.T, what, content string) map[string]any {
	t.Helper()
	docs := yamlDocs(t, what, content)
	fatalIf(t, len(docs) != 1, "%s: want one YAML document, found %d", what, len(docs))
	return docs[0]
}

func dig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func stringsOf(t *testing.T, what string, v any) []string {
	t.Helper()
	items, ok := v.([]any)
	fatalIf(t, !ok, "%s is %T, want a list of strings", what, v)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		fatalIf(t, !ok, "%s holds %T, want strings", what, it)
		out = append(out, s)
	}
	return out
}

func enrolmentEnv(t *testing.T, cc cloudConfig) map[string]string {
	t.Helper()
	f := cc.file(t, "/etc/mitstack/enrolment.env")
	env := map[string]string{}
	for _, line := range strings.Split(f.Content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		fatalIf(t, !ok, "enrolment.env line %q is not KEY=VALUE", line)
		env[k] = strings.Trim(v, `"'`)
	}
	return env
}

func (cc cloudConfig) allText(raw string) string {
	var b strings.Builder
	b.WriteString(raw)
	for _, f := range cc.WriteFiles {
		b.WriteString("\n")
		b.WriteString(f.Content)
	}
	b.WriteString("\n")
	b.WriteString(cc.runcmdText())
	return b.String()
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

	enrolScriptURLEnv        = "MITSTACK_ENROLMENT_URL"
	enrolScriptDirEnv        = "MITSTACK_ENROLMENT_DIR"
	enrolEndpointPath        = "/v1/cluster-enrolments"
	enrolScriptEnvFile       = "enrolment.env"
	enrolScriptJSONFile      = "enrolment.json"
	enrolManifestsDirEnv     = "MITSTACK_K3S_MANIFESTS_DIR"
	enrolManifestsDirDefault = "/var/lib/rancher/k3s/server/manifests"
	repoCredentialFile       = "05-cluster-repository.yaml"
	notificationSecretFile   = "05-argocd-notifications-secret.yaml"
	enrolRefusalBound        = 60 * time.Second
	enrolRetryBound          = 120 * time.Second

	repoTokenURLEnv     = "MITSTACK_REFRESH_URL"
	refreshEndpointPath = "/v1/cluster-repository-tokens"
	refreshRunBound     = 30 * time.Second

	reportScriptURLEnv  = "MITSTACK_REPORT_URL"
	tokenFileEnv        = "MITSTACK_TOKEN_FILE"
	hostDirEnv          = "MITSTACK_HOST_DIR"
	reportJournalctlEnv = "MITSTACK_JOURNALCTL"
	reportEndpointPath  = "/v1/cluster-reports"
	bootIDPath          = "/proc/sys/kernel/random/boot_id"
	reportRunBound      = 30 * time.Second

	reportOSReleaseEnv             = "MITSTACK_OS_RELEASE"
	reportCloudInitLogEnv          = "MITSTACK_CLOUD_INIT_LOG"
	reportK3sEnv                   = "MITSTACK_K3S"
	reportUserDataURLEnv           = "MITSTACK_USERDATA_URL"
	reportStateDirEnv              = "MITSTACK_STATE_DIR"
	reportUnattendedUpgradesLogEnv = "MITSTACK_UNATTENDED_UPGRADES_LOG"
	reportRebootRequiredEnv        = "MITSTACK_REBOOT_REQUIRED"
	reportSSEnv                    = "MITSTACK_SS"
	reportSystemctlEnv             = "MITSTACK_SYSTEMCTL"
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
	k3sRefused        = "The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?"

	enrolResponseBody = "{\n  \"repositoryToken\": \"enrol-sentinel-repository-token-0001\",\n  \"repositoryTokenExpiresAt\": \"2026-10-01T10:14:03Z\",\n" +
		"  \"reportToken\": \"enrol-sentinel-report-token-0001\",\n  \"notificationToken\": \"enrol-sentinel-notification-token-0001\"\n}\n"
	fixtureRepositoryToken          = "sentinel-cluster-repository-token-0003"
	fixtureNotificationToken        = "6e6f74696669636174696f6e2d73656e74696e656c2d746f6b656e2d30303034"
	fixtureRepositoryTokenExpiresAt = "2026-10-01T10:14:03Z"
	repositoryTokenUsername         = "x-access-token"
	fixtureReportToken              = "report-sentinel-token-0002"
	staleRepositoryToken            = "sentinel-stale-repository-token-0004"
	refreshedRepositoryToken        = "sentinel-refreshed-repository-token-0005"
	refreshedExpiresAt              = "2026-10-01T11:14:03Z"
	clusterSecretSentinel           = "sentinel-served-cluster-secret-0004"
	githubRefusal                   = "GitHub refused a read token for the cluster repository: 422 Resource not accessible by integration"
)

var (
	cannedJournal = testLines("report/journal.txt")
	cannedNodes   = testFile("k3s/nodes.json")
)

func writeIn(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), mode)
	fatalIf(t, err != nil, "writing %s error = %v; want nil", name, err)
	return path
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	return writeIn(t, t.TempDir(), name, content, 0o600)
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type enrolRun struct {
	dir, tmp, manifests string
	hostTar             string
	stdout, stderr      string
	err                 error
	elapsed             time.Duration
}

func (r enrolRun) output() string { return r.stdout + r.stderr }

type scriptRunOption func(env []string) []string

func withoutEnv(key string) scriptRunOption {
	return func(env []string) []string {
		return slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, key+"=") })
	}
}

func withEnv(key, value string) scriptRunOption {
	return func(env []string) []string { return append(withoutEnv(key)(env), key+"="+value) }
}

func withPATH(path string) scriptRunOption { return withEnv("PATH", path) }

func withPathPrefix(dir string) scriptRunOption {
	return func(env []string) []string {
		for _, kv := range env {
			if rest, ok := strings.CutPrefix(kv, "PATH="); ok {
				return withPATH(dir + string(os.PathListSeparator) + rest)(env)
			}
		}
		return withPATH(dir)(env)
	}
}

func runSh(t *testing.T, what, script string, bound time.Duration, run enrolRun, env []string, caFile string, opts []scriptRunOption) enrolRun {
	t.Helper()
	for _, tool := range []string{"sh", "curl", "python3"} {
		_, err := exec.LookPath(tool)
		fatalIf(t, err != nil, "%s is not on PATH, and the node has it: %v", tool, err)
	}
	return runShFile(t, what, writeTemp(t, what+".sh", script), bound, run, env, caFile, opts)
}

// runShFile runs the script at path, so a script that finds its siblings by its own path finds them.
func runShFile(t *testing.T, what, path string, bound time.Duration, run enrolRun, env []string, caFile string, opts []scriptRunOption) enrolRun {
	t.Helper()
	return runProgram(t, what, []string{"sh", path}, bound, run, env, caFile, opts)
}

func runProgram(t *testing.T, what string, argv []string, bound time.Duration, run enrolRun, env []string, caFile string, opts []scriptRunOption) enrolRun {
	t.Helper()
	env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + run.tmp, "TMPDIR=" + run.tmp}, env...)
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
	run.err = cmd.Run()
	run.elapsed = time.Since(start)
	run.stdout, run.stderr = stdout.String(), stderr.String()
	fatalIf(t, ctx.Err() != nil, "the %s script did not finish within %s:\n%s", what, bound, run.output())
	return run
}

func runEnrolScript(t *testing.T, script, env, url, caFile string, bound time.Duration, opts ...scriptRunOption) enrolRun {
	t.Helper()
	run := enrolRun{dir: t.TempDir(), tmp: t.TempDir(), manifests: t.TempDir()}
	writeIn(t, run.dir, enrolScriptEnvFile, env, 0o600)
	return runSh(t, "enrol", script, bound, run, []string{enrolScriptURLEnv + "=" + url, enrolScriptDirEnv + "=" + run.dir, enrolManifestsDirEnv + "=" + run.manifests}, caFile, opts)
}

// nodeAgentDir lays out the image's scripts as the Dockerfile's COPY lines do.
func nodeAgentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, line := range strings.Split(testRepoFile(t, "scripts/nodeagent/Dockerfile"), "\n") {
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
			writeIn(t, dir, name, testRepoFile(t, src), 0o755)
		}
	}
	return dir
}

func testRepoFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	fatalIf(t, err != nil, "reading %s: %v", path, err)
	return string(raw)
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
func runReportScript(t *testing.T, dir, token, url, caFile, journalctl string, opts ...scriptRunOption) enrolRun {
	t.Helper()
	agent, hostDir, shims := nodeAgentDir(t), t.TempDir(), t.TempDir()
	writeIn(t, shims, "nsenter", fakeNsenter, 0o755)
	writeIn(t, shims, "kubectl", "#!/bin/sh\nexec \"$"+reportK3sEnv+"\" kubectl \"$@\"\n", 0o755)
	tokenFile := writeIn(t, t.TempDir(), "token", token, 0o600)
	env := append([]string{reportScriptURLEnv + "=" + url, enrolScriptDirEnv + "=" + dir, reportJournalctlEnv + "=" + journalctl,
		hostDirEnv + "=" + hostDir, tokenFileEnv + "=" + tokenFile}, defaultEvidenceEnv(t)...)
	opts = append(opts, withPathPrefix(shims))
	tmp := t.TempDir()
	host := runShFile(t, "host", filepath.Join(agent, "mitstack-host"), reportRunBound, enrolRun{dir: dir, tmp: tmp}, env, caFile, opts)
	run := runShFile(t, "report", filepath.Join(agent, "mitstack-report"), reportRunBound, enrolRun{dir: dir, tmp: tmp}, env, caFile, opts)
	run.stdout, run.stderr, run.hostTar = host.stdout+run.stdout, host.stderr+run.stderr, filepath.Join(hostDir, "host.tar")
	if host.err != nil {
		run.err = host.err
	}
	return run
}

func runNodeScript(t *testing.T, script string, md *fakeMetadata, bound time.Duration) (dropInDir string, run enrolRun) {
	t.Helper()
	run = enrolRun{tmp: t.TempDir()}
	dropInDir = filepath.Join(run.tmp, "etc", "rancher", "k3s", "config.yaml.d")
	return dropInDir, runSh(t, "node", script, bound, run, []string{nodeScriptMetadataEnv + "=" + md.URL + metadataPath, nodeScriptDropInEnv + "=" + dropInDir}, "", nil)
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
	fatalIf(t, err != nil, "opening the socket that holds a closed port error = %v; want nil", err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	fatalIf(t, err != nil, "binding the socket that holds a closed port error = %v; want nil", err)
	sa, err := syscall.Getsockname(fd)
	fatalIf(t, err != nil, "reading the held port error = %v; want nil", err)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
}

func closedEndpoint(t *testing.T) string { return "https://" + closedAddr(t) + enrolEndpointPath }

type recordedEnrolRequest struct {
	Method, Path, Authorization, ContentType string
	Body                                     []byte
	TokenOnCmdline                           []string // every process command line that carried the token, the token itself redacted
	SawClient                                bool     // whether any process command line carried this server's URL, which shows the scan could see the client at all
}

type fakeEnrolment struct {
	*httptest.Server
	caFile   string
	token    string
	statuses []int

	mu       sync.Mutex
	okBody   string
	bodies   map[int]string
	requests []recordedEnrolRequest
}

func newFakeEnrolment(t *testing.T, token string, statuses ...int) *fakeEnrolment {
	t.Helper()
	fatalIf(t, len(statuses) == 0, "newFakeEnrolment needs at least one status to answer with")
	f := &fakeEnrolment{token: token, statuses: statuses, okBody: enrolResponseBody}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	f.caFile = writeTemp(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})))
	pre := exec.Command("curl", "-fsS", "--max-time", "10", f.Server.URL+"/preflight")
	pre.Env = []string{"PATH=" + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + f.caFile, "SSL_CERT_FILE=" + f.caFile}
	out, err := pre.CombinedOutput()
	fatalIf(t, err != nil, "curl cannot reach the test enrolment server over TLS, so no run below would reach it either: %v\n%s", err, out)
	return f
}

func (f *fakeEnrolment) endpoint() string { return f.Server.URL + enrolEndpointPath }

func (f *fakeEnrolment) refreshURL() string { return f.Server.URL + refreshEndpointPath }

func (f *fakeEnrolment) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/preflight" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	withToken, sawClient := scanCmdlines(f.token, f.Server.URL)
	f.mu.Lock()
	n := len(f.requests)
	f.requests = append(f.requests, recordedEnrolRequest{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
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

func (f *fakeEnrolment) answerStatusWith(status int, body string) {
	defer lock(&f.mu)()
	if f.bodies == nil {
		f.bodies = map[int]string{}
	}
	f.bodies[status] = body
}

func (f *fakeEnrolment) answerOKWith(body string) {
	defer lock(&f.mu)()
	f.okBody = body
}

func (f *fakeEnrolment) received() []recordedEnrolRequest {
	defer lock(&f.mu)()
	return slices.Clone(f.requests)
}

func scanCmdlines(token, url string) (withToken []string, sawURL bool) {
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

func renderedEnrolment(t *testing.T) (script cloudFile, env string) {
	t.Helper()
	_, cc := renderFixture(t)
	return cc.enrolScript(t), cc.file(t, "/etc/mitstack/"+enrolScriptEnvFile).Content
}

type sleepRecorder struct{ dir, log string }

func newSleepRecorder(t *testing.T) *sleepRecorder {
	t.Helper()
	r := &sleepRecorder{dir: t.TempDir(), log: filepath.Join(t.TempDir(), "sleep.log")}
	writeIn(t, r.dir, "sleep", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shQuote(r.log)+"\n", 0o755)
	return r
}

func (r *sleepRecorder) option() scriptRunOption { return withPathPrefix(r.dir) }

func (r *sleepRecorder) delays(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(r.log)
	fatalIf(t, err != nil && !errors.Is(err, fs.ErrNotExist), "reading the recorded sleeps: %v", err)
	return strings.Fields(string(raw))
}

func assertSlept(t *testing.T, sleeps *sleepRecorder, want ...string) {
	t.Helper()
	got := sleeps.delays(t)
	failIf(t, !slices.Equal(got, want), "the enrol script slept %v between attempts; want %v", got, want)
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
			writeIn(t, r.dir, name, "#!/bin/sh\n{ printf '%s' "+shQuote(name)+"; for a in \"$@\"; do printf ' %s' \"$a\"; done; printf '\\n'; } >> "+shQuote(r.log)+"\nexec "+shQuote(real)+" \"$@\"\n", 0o755)
		}
	}
	return r
}

func (r *argvRecorder) path() string { return r.dir + string(os.PathListSeparator) + os.Getenv("PATH") }

func (r *argvRecorder) commandLines(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(r.log)
	fatalIf(t, err != nil && !errors.Is(err, fs.ErrNotExist), "reading the recorded command lines: %v", err)
	return string(raw)
}

func assertNothingLeftHolding(t *testing.T, who, dir string, fragments []string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		failIf(t, readErr == nil && slices.ContainsFunc(fragments, func(f string) bool { return bytes.Contains(raw, []byte(f)) }), "%s left a secret behind in %s", who, path)
		return nil
	})
}

func enrolledDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	writeIn(t, dir, enrolScriptJSONFile, body, 0o600)
	return dir
}

func enrolledAnswer(t *testing.T) string {
	t.Helper()
	return tokenAnswer(t, fixtureRepositoryToken, fixtureReportToken)
}

func refreshAnswer(t *testing.T, token string) string {
	t.Helper()
	return enrolAnswer(t, map[string]any{"repositoryToken": token, "repositoryTokenExpiresAt": refreshedExpiresAt})
}

func newRefreshEndpoint(t *testing.T, statuses ...int) *fakeEnrolment {
	t.Helper()
	srv := newFakeEnrolment(t, fixtureReportToken, statuses...)
	srv.answerOKWith(refreshAnswer(t, refreshedRepositoryToken))
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
		reply(w, cmp.Or(a.status, http.StatusOK), a.body)
	}))
	t.Cleanup(md.Server.Close)
	return md
}

func (md *fakeMetadata) hitCount(path string) int {
	defer lock(&md.mu)()
	return md.hits[path]
}

type fakeTool struct{ path, runsFile string }

// toolAnswer answers the exact arguments args, or any arguments the shell pattern glob matches when glob is set.
type toolAnswer struct {
	args, stdout, stderr string
	exit                 int
	glob                 string
}

const fakeToolRunEnd = "--fake-tool-run-end--"

func newFakeTool(t *testing.T, name, stdout, stderr string, exit int, answers ...toolAnswer) fakeTool {
	t.Helper()
	dir := t.TempDir()
	f := fakeTool{path: filepath.Join(dir, name), runsFile: filepath.Join(dir, "runs")}
	emit := func(key, stdout, stderr string, exit int) string {
		out := writeIn(t, dir, key+".stdout", stdout, 0o600)
		errOut := writeIn(t, dir, key+".stderr", stderr, 0o600)
		return "cat " + shQuote(out) + "; cat " + shQuote(errOut) + " >&2; exit " + strconv.Itoa(exit)
	}
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + shQuote(f.runsFile) + "; done\nprintf '%s\\n' " + shQuote(fakeToolRunEnd) + " >> " + shQuote(f.runsFile) + "\ncase \"$*\" in\n"
	for i, a := range answers {
		pattern := shQuote(a.args)
		if a.glob != "" {
			pattern = a.glob
		}
		script += "  " + pattern + ") " + emit("answer-"+strconv.Itoa(i), a.stdout, a.stderr, a.exit) + " ;;\n"
	}
	writeIn(t, dir, name, script+"esac\n"+emit("canned", stdout, stderr, exit)+"\n", 0o755)
	return f
}

func (f fakeTool) runs(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(f.runsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	fatalIf(t, err != nil, "reading the fake tool's runs: %v", err)
	var out [][]string
	run := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == fakeToolRunEnd {
			out, run = append(out, run), []string{}
			continue
		}
		run = append(run, line)
	}
	return out
}

func (f fakeTool) ran(t *testing.T, want ...string) bool {
	t.Helper()
	return slices.ContainsFunc(f.runs(t), func(args []string) bool { return slices.Equal(args, want) })
}

func fakeUname(t *testing.T, kernel string) fakeTool {
	t.Helper()
	return newFakeTool(t, "uname", "", "uname: this fake answers only -r and -n\n", 1, toolAnswer{args: "-r", stdout: kernel + "\n"}, toolAnswer{args: "-n", stdout: fixtureNodeName + "\n"})
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
	fatalIf(t, hostNodeNameErr != nil || hostNodeNameVal == "", "uname -n names no node here (%v), and the fake k3s serves the kubelet's configuration for it", hostNodeNameErr)
	return hostNodeNameVal
}

type fakeJournal struct{ path, argsFile string }

func newFakeJournal(t *testing.T, lines []string) fakeJournal {
	t.Helper()
	dir := t.TempDir()
	writeIn(t, dir, "journal.txt", strings.Join(lines, "\n")+"\n", 0o600)
	writeIn(t, dir, "journalctl", testFile("fakes/journalctl.sh"), 0o755)
	return fakeJournal{path: filepath.Join(dir, "journalctl"), argsFile: filepath.Join(dir, "args")}
}

func (j fakeJournal) args(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(j.argsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	fatalIf(t, err != nil, "reading the fake journalctl's arguments: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

type fakeCurl struct{ dir, log string }

func newFakeCurl(t *testing.T, body string) fakeCurl {
	t.Helper()
	python, err := exec.LookPath("python3")
	fatalIf(t, err != nil, "python3 is not on PATH, and the fake curl runs on it: %v", err)
	dir, work := t.TempDir(), t.TempDir()
	c := fakeCurl{dir: dir, log: filepath.Join(work, "curl.log")}
	program, bodyFile := writeIn(t, work, "curl.py", testFile("fakes/curl.py"), 0o600), writeIn(t, work, "body", body, 0o600)
	writeIn(t, dir, "curl", "#!/bin/sh\nexec "+shQuote(python)+" "+shQuote(program)+" "+shQuote(c.log)+" "+shQuote(bodyFile)+" \"$@\"\n", 0o755)
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
	fatalIf(t, err != nil, "python3 is not on PATH, and the fake curl runs on it: %v", err)
	dir, work := t.TempDir(), t.TempDir()
	cfg, err := json.Marshal(map[string]any{"base": base, "routes": answers, "shimDir": dir})
	fatalIf(t, err != nil, "encoding the fake Argo CD curl's answers: %v", err)
	c := fakeCurl{dir: dir, log: filepath.Join(work, "curl.log")}
	program, config := writeIn(t, work, "argocd-curl.py", testFile("fakes/argocd-curl.py"), 0o600), writeIn(t, work, "routes.json", string(cfg), 0o600)
	writeIn(t, dir, "curl", "#!/bin/sh\nexec "+shQuote(python)+" "+shQuote(program)+" "+shQuote(c.log)+" "+shQuote(config)+" \"$@\"\n", 0o755)
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
	fatalIf(t, err != nil, "reading the fake curl's log: %v", err)
	var out []curlAttempt
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var a curlAttempt
		err := json.Unmarshal([]byte(line), &a)
		fatalIf(t, err != nil, "the fake curl's log line is not JSON: %v\n%s", err, line)
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
	return func(c *fakeK3sConfig) { c.Answers[readAdmissionFixtures] = mustJSON(doc) }
}

// k3sNodeFixtures gives mitstack-node an admission-fixtures ConfigMap, which a cluster has only once it is seeded.
func k3sNodeFixtures(data map[string]string) fakeK3sOption {
	doc := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "admission-fixtures", "namespace": "mitstack-node"}, "data": data}
	return func(c *fakeK3sConfig) { c.Answers["nodeAdmissionFixtures"] = mustJSON(doc) }
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
	fatalIf(t, err != nil, "python3 is not on PATH, and the fake k3s runs on it: %v", err)
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
	fatalIf(t, json.Unmarshal([]byte(testFile("k3s/admission-applies.json")), &applies) != nil, "testdata/k3s/admission-applies.json is not JSON")
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
	fatalIf(t, err != nil, "encoding the fake k3s's answers: %v", err)
	dir := t.TempDir()
	k := fakeK3s{path: filepath.Join(dir, "k3s"), argsFile: filepath.Join(dir, "args")}
	config, program := writeIn(t, dir, "answers.json", string(raw), 0o600), writeIn(t, dir, "k3s.py", testFile("fakes/k3s.py"), 0o600)
	// python3 runs by its absolute path, so a recorded PATH never sees it.
	writeIn(t, dir, "k3s", "#!/bin/sh\nexec "+shQuote(python)+" "+shQuote(program)+" "+shQuote(config)+" "+shQuote(k.argsFile)+" \"$@\"\n", 0o755)
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
	fatalIf(t, err != nil, "reading the fake k3s's record: %v", err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func (k fakeK3s) argvs(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	for _, line := range k.lines(t, ".jsonl") {
		var argv []string
		err := json.Unmarshal([]byte(line), &argv)
		fatalIf(t, err != nil, "the fake k3s recorded arguments that are not a JSON list: %v\n%s", err, line)
		out = append(out, argv)
	}
	return out
}

func (k fakeK3s) callTimes(t *testing.T) []time.Time {
	t.Helper()
	var out []time.Time
	for _, line := range k.lines(t, ".times") {
		secs, err := strconv.ParseFloat(line, 64)
		fatalIf(t, err != nil, "the fake k3s recorded a call time that is not a number: %q", line)
		out = append(out, time.Unix(0, int64(secs*float64(time.Second))))
	}
	return out
}

// defaultEvidenceEnv holds a fresh patch check, so the collector runs none unless a test asks, and fakes for the tools it would run.
func defaultEvidenceEnv(t *testing.T) []string {
	t.Helper()
	return []string{
		reportOSReleaseEnv + "=" + writeTemp(t, "os-release", testFile("report/os-release")),
		reportCloudInitLogEnv + "=" + writeTemp(t, "cloud-init-output.log", testFile("report/cloud-init-output.log")),
		reportK3sEnv + "=" + newFakeK3s(t).path,
		reportUserDataURLEnv + "=" + closedHTTPURL(t),
		enrolScriptURLEnv + "=" + closedEndpoint(t),
		reportSSEnv + "=" + newFakeTool(t, "ss", testFile("report/listeners.txt"), "", 0).path,
		reportSystemctlEnv + "=" + newFakeTool(t, "systemctl", cannedSSHUnits, "", cannedSSHUnitsExit, toolAnswer{args: autoUpgradeUnitsArgs, stdout: "enabled\nenabled\nenabled\n"}).path,
		reportNftEnv + "=" + newFakeTool(t, "nft", testFile("report/metadata-guard.txt"), "", 0).path,
		reportStateDirEnv + "=" + stateDirHolding(t, testFile("report/patch-check.json")),
		reportUnattendedUpgradesLogEnv + "=" + writeTemp(t, "unattended-upgrades.log", testFile("report/unattended-upgrades.log")),
		reportRebootRequiredEnv + "=" + filepath.Join(t.TempDir(), "reboot-required"),
		reportSystemdRunEnv + "=" + newFakeTool(t, "systemd-run", "", noScanUnit, 1).path,
		patchCheckAptGetEnv + "=" + newFakeTool(t, "apt-get", "", "", 0).path,
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
	writeIn(t, dir, patchCheckFile, check, 0o644)
	return dir
}

func rebootSentinel(t *testing.T, mtime time.Time, pkgs string) string {
	t.Helper()
	path := writeIn(t, t.TempDir(), "reboot-required", "*** System restart required ***\n", 0o644)
	writeIn(t, filepath.Dir(path), "reboot-required.pkgs", pkgs, 0o644)
	err := os.Chtimes(path, mtime, mtime)
	fatalIf(t, err != nil, "setting the sentinel's mtime: %v", err)
	return path
}

type reportRig struct {
	t        *testing.T
	token    string
	srv      *fakeEnrolment
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
	tools    map[string]fakeTool
	userData *fakeMetadata
	probe    *fakeEnrolment
	rec      *argvRecorder
	argocd   map[string]argocdAnswer
	curl     fakeCurl
	env      []scriptRunOption
	run      enrolRun
	req      recordedEnrolRequest
}

type reportOption func(*reportRig)

func newReportRig(t *testing.T, opts ...reportOption) *reportRig {
	t.Helper()
	r := &reportRig{t: t, token: fixtureReportToken, srv: newFakeEnrolment(t, fixtureReportToken, http.StatusOK),
		answer: enrolledAnswer(t), journal: cannedJournal, tools: map[string]fakeTool{}, dirFiles: map[string]string{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

func withPlatform(statuses ...int) reportOption {
	return func(r *reportRig) { r.srv = newFakeEnrolment(r.t, fixtureReportToken, statuses...) }
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
	return func(r *reportRig) { r.k3sPath = newFakeTool(r.t, "k3s", "", stderr, 1).path }
}
func withPrintingK3s(stdout string) reportOption {
	return func(r *reportRig) { r.k3sPath = newFakeTool(r.t, "k3s", stdout, "", 0).path }
}
func withEnvVar(key, value string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(key, value)) }
}
func withSource(key, name, content string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(key, writeTemp(r.t, name, content))) }
}
func withStateDir(check string) reportOption {
	return func(r *reportRig) { r.env = append(r.env, withEnv(reportStateDirEnv, stateDirHolding(r.t, check))) }
}
func withHourOldCheck() reportOption {
	return func(r *reportRig) {
		dir := stateDirHolding(r.t, testFile("report/patch-check.json"))
		old := time.Now().Add(-61 * time.Minute)
		fatalIf(r.t, os.Chtimes(filepath.Join(dir, patchCheckFile), old, old) != nil, "ageing the kept patch check")
		r.env = append(r.env, withEnv(reportStateDirEnv, dir))
	}
}
func withRebootSentinel(mtime time.Time, pkgs string) reportOption {
	return func(r *reportRig) {
		r.env = append(r.env, withEnv(reportRebootRequiredEnv, rebootSentinel(r.t, mtime, pkgs)))
	}
}
func withTool(key, name, stdout, stderr string, exit int, answers ...toolAnswer) reportOption {
	return func(r *reportRig) {
		r.tools[name] = newFakeTool(r.t, name, stdout, stderr, exit, answers...)
		r.env = append(r.env, withEnv(key, r.tools[name].path))
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
		}{{reportSSEnv, "ss", testFile("report/listeners.txt"), 0}, {reportSystemctlEnv, "systemctl", cannedSSHUnits, cannedSSHUnitsExit}, {reportNftEnv, "nft", testFile("report/metadata-guard.txt"), 0}} {
			r.tools[tool.name] = newFakeTool(r.t, tool.name, tool.stdout, "", tool.exit)
			dirs = append(dirs, filepath.Dir(r.tools[tool.name].path))
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
			r.probe = newFakeEnrolment(r.t, token, statuses...)
			url = r.probe.endpoint()
		}
		r.env = append(r.env, withEnv(enrolScriptURLEnv, url))
	}
}

func (r *reportRig) exec() enrolRun {
	t := r.t
	t.Helper()
	if r.dir == "" {
		r.dir = enrolledDir(t, r.answer)
		if r.nodeEnv {
			_, env := renderedEnrolment(t)
			writeIn(t, r.dir, enrolScriptEnvFile, env, 0o600)
		}
		for name, content := range r.dirFiles {
			writeIn(t, r.dir, name, content, 0o600)
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
	url, ca := r.srv.URL+reportEndpointPath, r.srv.caFile
	if r.url != "" {
		url, ca = r.url, ""
	}
	opts := append([]scriptRunOption{withEnv(reportK3sEnv, k3sPath)}, r.env...)
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
	before := len(r.srv.received())
	if r.exec(); r.run.err != nil {
		t.Fatalf("the report script failed: %v\n%s", r.run.err, truncate(r.run.output(), 2000))
	}
	reqs := r.srv.received()
	n := len(reqs) - before
	fatalIf(t, n != 1, "the report script sent %d reports, want exactly one\n%s", n, truncate(r.run.output(), 2000))
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

var cannedK3sReleases = mustJSON([]any{
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
	f.caFile = writeTemp(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})))
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
	reply(w, a.status, a.body)
}

func (f *fakeK3sFeeds) answer(path string, status int, body string) {
	defer lock(&f.mu)()
	f.answers[path] = httpAnswer{status, body}
}

func (f *fakeK3sFeeds) requests(path string) int {
	defer lock(&f.mu)()
	return len(f.queries[path])
}

func (f *fakeK3sFeeds) channelsURL() string { return f.URL + k3sChannelsPath }

func (f *fakeK3sFeeds) releasesURL() string { return f.URL + k3sReleasesPath + "?per_page=100" }

func bootDirWith(t *testing.T, link string, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		writeIn(t, dir, name, "kernel image "+name+"\n", 0o600)
	}
	if link != "" {
		for _, l := range []string{"vmlinuz", "vmlinuz.old"} {
			err := os.Symlink(link, filepath.Join(dir, l))
			fatalIf(t, err != nil, "linking /boot/%s: %v", l, err)
		}
	}
	return dir
}

type patchCheckNode struct {
	k3s            string
	aptGet         fakeTool
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
		aptGet:         newFakeTool(t, "apt-get", cannedAptNothingPending, "", 0),
		uname:          fakeUname(t, runningKernel).path,
		osRelease:      writeTemp(t, "os-release", testFile("report/os-release")),
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
	fatalIf(t, err != nil, "the clock %q is not RFC 3339: %v", now, err)
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
		fatalIf(t, err != nil && !errors.Is(err, os.ErrNotExist), "removing the update stamp: %v", err)
		return
	}
	clock := time.Now()
	if now != "" {
		clock = parseClock(t, now)
	}
	writeIn(t, filepath.Dir(n.updateStamp), filepath.Base(n.updateStamp), "", 0o644)
	at := clock.Add(-n.stampAge)
	fatalIf(t, os.Chtimes(n.updateStamp, at, at) != nil, "setting the update stamp's mtime")
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
	fatalIf(t, !ok, "%s.%s is %#v, want an object:\n%s", patchCheckFile, name, r.result[name], r.raw)
	return p
}

func (n *patchCheckNode) run(t *testing.T, now string, opts ...scriptRunOption) patchCheckRun {
	t.Helper()
	n.touchStamp(t, now)
	env := []string{
		"CURL_CA_BUNDLE=" + n.feeds.caFile, "SSL_CERT_FILE=" + n.feeds.caFile, reportK3sEnv + "=" + n.k3s, patchCheckAptGetEnv + "=" + n.aptGet.path,
		patchCheckUnameEnv + "=" + n.uname, reportOSReleaseEnv + "=" + n.osRelease, patchCheckBootDirEnv + "=" + n.bootDir, reportStateDirEnv + "=" + n.stateDir,
		reportRebootRequiredEnv + "=" + n.rebootRequired, patchCheckChannelsURLEnv + "=" + n.feeds.channelsURL(), patchCheckReleasesURLEnv + "=" + n.feeds.releasesURL(),
		patchCheckUpdateStampEnv + "=" + n.updateStamp,
	}
	if now != "" {
		env = append(env, patchCheckNowEnv+"="+now)
	}
	res := runSh(t, "patch-check", testRepoFile(t, "scripts/mitstack-patch-check.sh"), patchCheckRunBound, enrolRun{tmp: t.TempDir()}, env, "", opts)
	run := patchCheckRun{stdout: res.stdout, stderr: res.stderr}
	var exitErr *exec.ExitError
	switch {
	case res.err == nil:
	case errors.As(res.err, &exitErr):
		run.exit = exitErr.ExitCode()
	default:
		t.Fatalf("running the patch check: %v\n%s", res.err, run.output())
	}
	raw, readErr := os.ReadFile(filepath.Join(n.stateDir, patchCheckFile))
	fatalIf(t, readErr != nil, "the patch check wrote no %s (exit %d): %v\n%s", patchCheckFile, run.exit, readErr, run.output())
	run.raw = raw
	err := json.Unmarshal(raw, &run.result)
	fatalIf(t, err != nil || run.result == nil, "%s is not a JSON object: %v\n%s", patchCheckFile, err, raw)
	return run
}

func reply(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func renderOK(t *testing.T, in UserDataInputs) string {
	t.Helper()
	ud, err := RenderUserData(in)
	fatalIf(t, err != nil, "RenderUserData error = %v; want nil", err)
	return ud
}

func renderCC(t *testing.T, in UserDataInputs) (string, cloudConfig) {
	t.Helper()
	ud := renderOK(t, in)
	return ud, parseUserData(t, ud)
}

func lock(mu *sync.Mutex) func() {
	mu.Lock()
	return mu.Unlock
}

func failIf(t *testing.T, bad bool, format string, args ...any) {
	t.Helper()
	if bad {
		t.Errorf(format, args...)
	}
}

func fatalIf(t *testing.T, bad bool, format string, args ...any) {
	t.Helper()
	if bad {
		t.Fatalf(format, args...)
	}
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
