package cluster

// openbaoscript_test.go runs mitstack-openbao, as the node agent's image carries it, with the real python3, gpg and
// openssl against a fake OpenBao served over TLS and a fake GitHub.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const (
	fakeRootToken   = "s.fake-root-token-0123456789"
	fakeRecoveryKey = "6b1e0c3a5d7f9b2e4c6a8d0f1b3e5c7a9d2f4b6e8c0a1d3f5b7e9c2a4d6f8b0e"
	fakeAppToken    = "ghs_fakeinstallationtoken"
	fakeWriterToken = "s.fake-writer-token"
	fakeSAToken     = "eyJfake.service-account.token"
	fakeK8sAccessor = "auth_kubernetes_f1e2d3c4"
)

// openBaoCall is one request either fake received, in the order the script sent them.
type openBaoCall struct {
	method, path, token string
	body                map[string]any
}

type openBaoBootFakes struct {
	t           *testing.T
	owner       *openpgp.Entity
	appKey      *rsa.PrivateKey
	mu          sync.Mutex
	calls       []openBaoCall
	initialised bool
	authEnabled bool
	files       map[string]string
	bao, github *httptest.Server
}

func newOpenBaoBootFakes(t *testing.T, owner *openpgp.Entity) *openBaoBootFakes {
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fatalIf(t, err != nil, "generating the App's key: %v", err)
	f := &openBaoBootFakes{t: t, owner: owner, appKey: appKey, files: map[string]string{}}
	f.bao = httptest.NewTLSServer(http.HandlerFunc(f.serveOpenBao))
	f.github = httptest.NewServer(http.HandlerFunc(f.serveGitHub))
	t.Cleanup(func() { f.bao.Close(); f.github.Close() })
	return f
}

func (f *openBaoBootFakes) record(r *http.Request, token string) map[string]any {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	defer lock(&f.mu)()
	f.calls = append(f.calls, openBaoCall{method: r.Method, path: r.URL.Path, token: token, body: body})
	return body
}

func (f *openBaoBootFakes) serveOpenBao(w http.ResponseWriter, r *http.Request) {
	f.record(r, r.Header.Get("X-Vault-Token"))
	defer lock(&f.mu)()
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/sys/init":
		reply(w, http.StatusOK, fmt.Sprintf(`{"initialized":%t}`, f.initialised))
	case "PUT /v1/sys/init":
		f.initialised = true
		reply(w, http.StatusOK, fmt.Sprintf(`{"root_token":%q,"recovery_keys_base64":[%q]}`, fakeRootToken, f.encryptBinary(fakeRecoveryKey)))
	case "GET /v1/sys/mounts":
		reply(w, http.StatusOK, `{"data":{"sys/":{}}}`)
	case "GET /v1/sys/auth":
		if f.authEnabled {
			reply(w, http.StatusOK, `{"data":{"token/":{"accessor":"auth_token_0a1b2c3d"},"kubernetes/":{"accessor":"`+fakeK8sAccessor+`","type":"kubernetes"}}}`)
			return
		}
		reply(w, http.StatusOK, `{"data":{"token/":{"accessor":"auth_token_0a1b2c3d"}}}`)
	case "POST /v1/sys/auth/kubernetes":
		f.authEnabled = true
		w.WriteHeader(http.StatusNoContent)
	case "POST /v1/auth/kubernetes/login":
		reply(w, http.StatusOK, fmt.Sprintf(`{"auth":{"client_token":%q}}`, fakeWriterToken))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *openBaoBootFakes) encryptBinary(plain string) string {
	var b bytes.Buffer
	w, err := openpgp.Encrypt(&b, []*openpgp.Entity{f.owner}, nil, nil, nil)
	fatalIf(f.t, err != nil, "encrypting the recovery key: %v", err)
	_, _ = w.Write([]byte(plain))
	fatalIf(f.t, w.Close() != nil, "encrypting the recovery key")
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// serveGitHub mints an installation token only for a JWT the App's key signed, and serves the contents API.
func (f *openBaoBootFakes) serveGitHub(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	body := f.record(r, auth)
	defer lock(&f.mu)()
	if r.URL.Path == "/app/installations/"+fixtureInstallationID+"/access_tokens" {
		if !f.signedByTheApp(auth) {
			reply(w, http.StatusUnauthorized, `{}`)
			return
		}
		reply(w, http.StatusCreated, fmt.Sprintf(`{"token":%q}`, fakeAppToken))
		return
	}
	file, ok := strings.CutPrefix(r.URL.Path, "/repos/"+fixtureRepo+"/contents/")
	if !ok || auth != fakeAppToken {
		reply(w, http.StatusNotFound, `{}`)
		return
	}
	content, found := f.files[file]
	switch {
	case r.Method == http.MethodGet && found:
		reply(w, http.StatusOK, fmt.Sprintf(`{"content":%q}`, base64.StdEncoding.EncodeToString([]byte(content))))
	case r.Method == http.MethodPut && !found:
		raw, _ := base64.StdEncoding.DecodeString(fmt.Sprint(body["content"]))
		f.files[file] = string(raw)
		reply(w, http.StatusCreated, `{}`)
	default:
		reply(w, http.StatusNotFound, `{}`)
	}
}

func (f *openBaoBootFakes) signedByTheApp(jwt string) bool {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	return err == nil && rsa.VerifyPKCS1v15(&f.appKey.PublicKey, crypto.SHA256, sum[:], sig) == nil &&
		strings.Contains(string(claims), `"iss": "`+fixtureGitHubAppID+`"`)
}

func (f *openBaoBootFakes) callsSoFar() []openBaoCall {
	defer lock(&f.mu)()
	return slices.Clone(f.calls)
}

func (f *openBaoBootFakes) indexOf(method, path string) int {
	return slices.IndexFunc(f.callsSoFar(), func(c openBaoCall) bool { return c.method == method && c.path == path })
}

// openBaoScript prepares mitstack-openbao's environment, with the recipient and the App's key as the pods mount them.
func (f *openBaoBootFakes) openBaoScript(t *testing.T, recipient string, command string) *exec.Cmd {
	t.Helper()
	for _, tool := range []string{"python3", "gpg", "openssl"} {
		_, err := exec.LookPath(tool)
		fatalIf(t, err != nil, "%s is not on PATH, and the node agent's image has it: %v", tool, err)
	}
	dir := t.TempDir()
	appKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.appKey)})
	cmd := exec.Command("python3", "-I", filepath.Join(nodeAgentDir(t), "mitstack-openbao"), command)
	cmd.Env = append(os.Environ(),
		"MITSTACK_OPENBAO_ADDR="+f.bao.URL, "MITSTACK_GITHUB_API_URL="+f.github.URL,
		"MITSTACK_OPENBAO_CA="+writeIn(t, dir, "ca.crt", certificatePEM(f.bao.Certificate()), 0o644),
		"MITSTACK_RECIPIENT_FILE="+writeIn(t, dir, "recipient.asc", recipient, 0o644),
		"MITSTACK_APP_KEY_FILE="+writeIn(t, dir, "private-key", string(appKey), 0o600),
		"MITSTACK_SA_TOKEN_FILE="+writeIn(t, dir, "token", fakeSAToken, 0o600),
		"MITSTACK_REPOSITORY="+fixtureRepo, "MITSTACK_GITHUB_APP_ID="+fixtureGitHubAppID, "MITSTACK_GITHUB_INSTALLATION_ID="+fixtureInstallationID,
		"MITSTACK_RETRY_SECONDS=0.05", "GNUPGHOME="+filepath.Join(dir, "gnupg"), "KUBERNETES_SERVICE_HOST=10.43.0.1")
	return cmd
}

func runOpenBaoInit(t *testing.T, f *openBaoBootFakes, recipient string) (string, error) {
	t.Helper()
	cmd := f.openBaoScript(t, recipient, "init")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	fatalIf(t, cmd.Start() != nil, "starting mitstack-openbao init")
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("mitstack-openbao init ran past a minute: %s", out.String())
		return "", nil
	}
}

func TestOpenBaoInit_CommitsTheRootTokenAndRecoveryKeyOnlyAsPGPMessagesBeforeItSetsOpenBaoUp(t *testing.T) {
	owner, recipient := ownerKey(t)
	f := newOpenBaoBootFakes(t, owner)

	out, err := runOpenBaoInit(t, f, recipient)

	fatalIf(t, err != nil, "mitstack-openbao init failed: %v\n%s", err, out)
	initCall := f.callsSoFar()[f.indexOf("PUT", "/v1/sys/init")]
	keys, _ := initCall.body["recovery_pgp_keys"].([]any)
	fatalIf(t, len(keys) != 1, "the init passed %d recovery PGP keys, want the owner's alone", len(keys))
	binary, err := base64.StdEncoding.DecodeString(fmt.Sprint(keys[0]))
	fatalIf(t, err != nil, "the recovery PGP key is not base64: %v", err)
	sent, err := openpgp.ReadKeyRing(bytes.NewReader(binary))
	fatalIf(t, err != nil || len(sent) != 1 || sent[0].PrimaryKey.KeyId != owner.PrimaryKey.KeyId, "the recovery PGP key is not the owner's binary key: %v", err)
	failIf(t, initCall.body["recovery_shares"] != 1.0 || initCall.body["recovery_threshold"] != 1.0 || initCall.body["root_token_pgp_key"] != nil,
		"the init asked for %v, want one recovery share of threshold one and a plain root token", initCall.body)

	committed, ok := f.files["openbao-init.asc"]
	fatalIf(t, !ok, "the cluster repository holds no openbao-init.asc:\n%s", out)
	messages := strings.SplitAfter(committed, "-----END PGP MESSAGE-----\n")
	fatalIf(t, len(messages) != 3 || messages[2] != "", "openbao-init.asc holds %d PGP messages, want the root token's and the recovery key's", len(messages)-1)
	failIf(t, decryptFor(t, owner, messages[0][strings.Index(messages[0], "-----BEGIN"):]) != fakeRootToken, "the first message does not decrypt to the root token")
	failIf(t, decryptFor(t, owner, messages[1][strings.Index(messages[1], "-----BEGIN"):]) != fakeRecoveryKey, "the second message does not decrypt to the recovery key")
	for _, secret := range []string{fakeRootToken, fakeRecoveryKey} {
		failIf(t, strings.Contains(committed, secret) || strings.Contains(out, secret), "a plain secret reached the repository or the log")
	}
	token := f.callsSoFar()[f.indexOf("POST", "/app/installations/"+fixtureInstallationID+"/access_tokens")].body
	failIf(t, fmt.Sprint(token["repositories"]) != "["+fixtureRepoName+"]" || fmt.Sprint(token["permissions"]) != "map[contents:write]",
		"the App token asked for %v, want contents:write on %s alone", token, fixtureRepoName)

	commit := f.indexOf("PUT", "/repos/"+fixtureRepo+"/contents/openbao-init.asc")
	var setUp []string
	for i, c := range f.callsSoFar() {
		if c.token == fakeRootToken && !strings.HasPrefix(c.path, "/v1/sys/init") {
			failIf(t, i < commit, "%s %s ran with the root token before openbao-init.asc was committed", c.method, c.path)
			setUp = append(setUp, c.method+" "+c.path+" "+fmt.Sprint(c.body))
		}
	}
	for _, want := range []string{
		"POST /v1/sys/mounts/kv map[options:map[version:2] type:kv]",
		"POST /v1/sys/auth/kubernetes map[type:kubernetes]",
		"POST /v1/auth/kubernetes/config map[kubernetes_host:https://10.43.0.1:443]",
		"PUT /v1/sys/policies/acl/argocd-github-app map[policy:path \"kv/data/argocd/github-app\" {\n  capabilities = [\"read\"]\n}\n]",
		"PUT /v1/sys/policies/acl/github-app-writer map[policy:path \"kv/data/argocd/github-app\" {\n  capabilities = [\"create\", \"update\"]\n}\n]",
		"POST /v1/auth/kubernetes/role/argocd map[bound_service_account_names:[openbao-argocd] bound_service_account_namespaces:[argocd] policies:[argocd-github-app] ttl:15m]",
		"POST /v1/auth/kubernetes/role/github-app-writer map[bound_service_account_names:[github-app-writer] bound_service_account_namespaces:[mitstack-node] policies:[github-app-writer] ttl:5m]",
	} {
		failIf(t, !slices.Contains(setUp, want), "the setup never sent %q; it sent %q", want, setUp)
	}
}

// lockedBuffer collects a running script's output, which the test reads while the script still writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) { defer lock(&l.mu)(); return l.b.Write(p) }

func (l *lockedBuffer) String() string { defer lock(&l.mu)(); return l.b.String() }

func certificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// otherAuthority is a self-signed authority that signed none of the fake OpenBao's certificates.
func otherAuthority(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIf(t, err != nil, "generating the other authority's key: %v", err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another authority"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	fatalIf(t, err != nil, "signing the other authority: %v", err)
	cert, err := x509.ParseCertificate(der)
	fatalIf(t, err != nil, "reading the other authority: %v", err)
	return certificatePEM(cert)
}

func TestOpenBaoScript_SendsNothingToAnOpenBaoItCannotVerify(t *testing.T) {
	for _, c := range []struct {
		name, env, want string
	}{
		{"a certificate another authority signed", "MITSTACK_OPENBAO_CA=" + writeIn(t, t.TempDir(), "other.crt", otherAuthority(t), 0o644), "CERTIFICATE_VERIFY_FAILED"},
		{"a plain http address", "MITSTACK_OPENBAO_ADDR=http://127.0.0.1:8200", "over https alone"},
	} {
		t.Run(c.name, func(t *testing.T) {
			owner, recipient := ownerKey(t)
			f := newOpenBaoBootFakes(t, owner)
			cmd := f.openBaoScript(t, recipient, "init")
			cmd.Env = append(cmd.Env, c.env)
			out := &lockedBuffer{}
			cmd.Stdout, cmd.Stderr = out, out
			fatalIf(t, cmd.Start() != nil, "starting mitstack-openbao init")
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			for !strings.Contains(out.String(), c.want) && ctx.Err() == nil {
				time.Sleep(20 * time.Millisecond)
			}

			failIf(t, !strings.Contains(out.String(), c.want), "mitstack-openbao init against %s said %q, want it to name %s", c.name, out.String(), c.want)
			failIf(t, len(f.callsSoFar()) != 0, "mitstack-openbao init against %s sent %d requests, want none", c.name, len(f.callsSoFar()))
		})
	}
}

func TestOpenBaoInit_StopsWithoutInitialisingWhenItCouldNotHandTheKeysBack(t *testing.T) {
	owner, recipient := ownerKey(t)
	noEncryption := *owner
	noEncryption.Subkeys = nil
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	fatalIf(t, err != nil || noEncryption.Serialize(w) != nil || w.Close() != nil, "armoring a key that cannot encrypt")
	signOnly := b.String()
	for _, c := range []struct {
		name, recipient, want string
		initialised, recorded bool
		fails                 bool
	}{
		{"a recipient that cannot encrypt", signOnly, "cannot encrypt", false, false, true},
		{"an initialised store with no openbao-init.asc", recipient, "holds no openbao-init.asc", true, false, true},
		{"an initialised store with openbao-init.asc", recipient, "holds openbao-init.asc; this Job no longer holds the root token, so it sets nothing up", true, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newOpenBaoBootFakes(t, owner)
			f.initialised = c.initialised
			if c.recorded {
				f.files["openbao-init.asc"] = "recorded"
			}

			out, err := runOpenBaoInit(t, f, c.recipient)

			failIf(t, (err != nil) != c.fails, "mitstack-openbao init with %s returned %v, want failure %t:\n%s", c.name, err, c.fails, out)
			failIf(t, !strings.Contains(out, c.want), "mitstack-openbao init with %s said %q, want it to name %q", c.name, out, c.want)
			failIf(t, f.indexOf("PUT", "/v1/sys/init") >= 0, "mitstack-openbao init with %s initialised OpenBao", c.name)
		})
	}
}

func TestOpenBaoWriteAppKey_WritesTheKeyUnderTheWriterRoleAndAgainWhenItChanges(t *testing.T) {
	owner, recipient := ownerKey(t)
	f := newOpenBaoBootFakes(t, owner)
	cmd := f.openBaoScript(t, recipient, "write-app-key")
	keyFile := strings.TrimPrefix(cmd.Env[slices.IndexFunc(cmd.Env, func(e string) bool { return strings.HasPrefix(e, "MITSTACK_APP_KEY_FILE=") })], "MITSTACK_APP_KEY_FILE=")
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	fatalIf(t, cmd.Start() != nil, "starting mitstack-openbao write-app-key")
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	written := func() []string {
		var keys []string
		for _, c := range f.callsSoFar() {
			if c.method == "POST" && c.path == "/v1/kv/data/argocd/github-app" && c.token == fakeWriterToken {
				keys = append(keys, fmt.Sprint(c.body["data"].(map[string]any)["private-key"]))
			}
		}
		return keys
	}
	waitFor := func(n int) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		for len(written()) < n && ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
		fatalIf(t, len(written()) < n, "the writer wrote the key %d times, want %d:\n%s", len(written()), n, out.String())
	}

	waitFor(1)
	rotated := testRepoFile(t, "testdata/boot/github-app.pem")
	writeIn(t, filepath.Dir(keyFile), filepath.Base(keyFile), rotated, 0o600)
	waitFor(2)

	failIf(t, written()[0] == rotated || written()[1] != rotated, "the writer wrote %d keys, want the mounted key and then the rotated one", len(written()))
	login := f.callsSoFar()[f.indexOf("POST", "/v1/auth/kubernetes/login")].body
	failIf(t, login["role"] != "github-app-writer" || login["jwt"] != fakeSAToken, "the writer logged in as %v, want the role github-app-writer with its service account's token", login)
	failIf(t, strings.Contains(out.String(), "PRIVATE KEY"), "the writer logged the App's key")
}

func TestOpenBaoInit_GivesEachSliceNamespaceItsOwnAppsPathAndTheAppSecretsWriterTheAppsPathsAlone(t *testing.T) {
	owner, recipient := ownerKey(t)
	f := newOpenBaoBootFakes(t, owner)

	out, err := runOpenBaoInit(t, f, recipient)

	fatalIf(t, err != nil, "mitstack-openbao init failed: %v\n%s", err, out)
	calls := f.callsSoFar()
	enabled := f.indexOf("POST", "/v1/sys/auth/kubernetes")
	reader := f.indexOf("PUT", "/v1/sys/policies/acl/app-secrets-reader")
	fatalIf(t, enabled < 0 || reader < enabled, "the setup enabled Kubernetes auth at call %d and wrote app-secrets-reader at call %d, want both, in that order:\n%s", enabled, reader, out)
	readAccessor := slices.IndexFunc(calls[enabled:reader], func(c openBaoCall) bool {
		return c.method == "GET" && c.path == "/v1/sys/auth" && c.token == fakeRootToken
	})
	failIf(t, readAccessor < 0, "the setup never read sys/auth between enabling Kubernetes auth and writing app-secrets-reader, so it cannot know the accessor")

	sent := map[string]string{}
	for _, c := range calls {
		if c.token == fakeRootToken {
			sent[c.method+" "+c.path] = fmt.Sprint(c.body)
		}
	}
	namespace := "{{identity.entity.aliases." + fakeK8sAccessor + ".metadata.service_account_namespace}}"
	wantReader := "path \"kv/data/apps/" + namespace + "/*\" {\n  capabilities = [\"read\"]\n}\n" +
		"path \"kv/metadata/apps/" + namespace + "/*\" {\n  capabilities = [\"read\", \"list\"]\n}\n"
	for key, want := range map[string]string{
		"PUT /v1/sys/policies/acl/app-secrets-reader":      "map[policy:" + wantReader + "]",
		"PUT /v1/sys/policies/acl/app-secrets-writer":      "map[policy:path \"kv/data/apps/*\" {\n  capabilities = [\"create\", \"update\"]\n}\n]",
		"POST /v1/auth/kubernetes/role/app-secrets":        "map[bound_service_account_names:[app] bound_service_account_namespaces:[app-*] policies:[app-secrets-reader] ttl:15m]",
		"POST /v1/auth/kubernetes/role/app-secrets-writer": "map[bound_service_account_names:[app-secrets-writer] bound_service_account_namespaces:[mitstack-node] policies:[app-secrets-writer] ttl:5m]",
	} {
		failIf(t, sent[key] != want, "the setup sent %s with %q, want %q", key, sent[key], want)
	}

	policy, _ := calls[reader].body["policy"].(string)
	for _, m := range regexp.MustCompile(`path "([^"]*)" \{\n  capabilities = \[([^\]]*)\]`).FindAllStringSubmatch(policy, -1) {
		own := strings.HasPrefix(m[1], "kv/data/apps/"+namespace+"/") || strings.HasPrefix(m[1], "kv/metadata/apps/"+namespace+"/")
		failIf(t, !own, "app-secrets-reader grants %q, which reaches past the signed-in namespace's own apps path", m[1])
		for _, write := range []string{"create", "update", "delete", "patch", "sudo"} {
			failIf(t, strings.Contains(m[2], `"`+write+`"`), "app-secrets-reader grants %s on %q, want reads alone", write, m[1])
		}
	}
}

// kubeletSecretVolume lays a Secret out as the kubelet mounts it: the keys in a timestamped directory that ..data
// links to, and each key a link through ..data.
type kubeletSecretVolume struct {
	t   *testing.T
	dir string
	n   int
}

func newKubeletSecretVolume(t *testing.T, data map[string]string) *kubeletSecretVolume {
	t.Helper()
	v := &kubeletSecretVolume{t: t, dir: t.TempDir()}
	v.swap(data)
	for key := range data {
		fatalIf(t, os.Symlink(filepath.Join("..data", key), filepath.Join(v.dir, key)) != nil, "linking %s", key)
	}
	return v
}

// swap writes a new timestamped directory and repoints ..data at it in one rename, as the kubelet updates a Secret.
func (v *kubeletSecretVolume) swap(data map[string]string) {
	v.t.Helper()
	v.n++
	stamp := fmt.Sprintf("..2026_10_19_10_00_%02d.%09d", v.n, v.n)
	fatalIf(v.t, os.Mkdir(filepath.Join(v.dir, stamp), 0o755) != nil, "creating %s", stamp)
	for key, value := range data {
		writeIn(v.t, filepath.Join(v.dir, stamp), key, value, 0o440)
	}
	fatalIf(v.t, os.Symlink(stamp, filepath.Join(v.dir, "..data_tmp")) != nil, "linking ..data_tmp")
	fatalIf(v.t, os.Rename(filepath.Join(v.dir, "..data_tmp"), filepath.Join(v.dir, "..data")) != nil, "repointing ..data")
}

func TestOpenBaoWriteAppSecrets_WritesEachNamespacesKeysToItsOwnPathAndAgainWhenOneChanges(t *testing.T) {
	owner, recipient := ownerKey(t)
	f := newOpenBaoBootFakes(t, owner)
	mounted := map[string]string{
		"app-a.GREETING": "hello-a", "app-a.DATABASE_URL": "postgres://a", "app-b.GREETING": "hello-b",
		"no-namespace": "dropped-1", "App_C.GREETING": "dropped-2", "-c.GREETING": "dropped-3", "app-d.": "dropped-4",
	}
	volume := newKubeletSecretVolume(t, mounted)
	cmd := f.openBaoScript(t, recipient, "write-app-secrets")
	cmd.Env = append(cmd.Env, "MITSTACK_APP_SECRETS_DIR="+volume.dir)
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	fatalIf(t, cmd.Start() != nil, "starting mitstack-openbao write-app-secrets")
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	written := func(namespace string) []string {
		var data []string
		for _, c := range f.callsSoFar() {
			if c.method == "POST" && c.path == "/v1/kv/data/apps/"+namespace+"/env" && c.token == fakeWriterToken {
				data = append(data, fmt.Sprint(c.body["data"]))
			}
		}
		return data
	}
	waitUntil := func(what string, done func() bool) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		for !done() && ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
		fatalIf(t, !done(), "the writer never %s:\n%s", what, out.String())
	}

	waitUntil("wrote app-a and app-b", func() bool { return len(written("app-a")) >= 1 && len(written("app-b")) >= 1 })
	mounted["app-a.GREETING"] = "hello-again"
	volume.swap(mounted)
	waitUntil("wrote app-a's changed value", func() bool { return len(written("app-a")) >= 2 })
	// Twenty of the writer's 50ms polls, so a needless second write of app-b has time to show.
	time.Sleep(20 * 50 * time.Millisecond)

	failIf(t, !slices.Equal(written("app-a"), []string{"map[DATABASE_URL:postgres://a GREETING:hello-a]", "map[DATABASE_URL:postgres://a GREETING:hello-again]"}),
		"the writer wrote apps/app-a/env as %q, want the mounted keys and then the changed value", written("app-a"))
	failIf(t, !slices.Equal(written("app-b"), []string{"map[GREETING:hello-b]"}),
		"the writer wrote apps/app-b/env as %q, want its one key once, since it never changed", written("app-b"))
	for _, c := range f.callsSoFar() {
		if strings.HasPrefix(c.path, "/v1/kv/") {
			failIf(t, c.path != "/v1/kv/data/apps/app-a/env" && c.path != "/v1/kv/data/apps/app-b/env", "the writer wrote %s, want only the env path of a namespace a key names", c.path)
		}
	}
	login := f.callsSoFar()[f.indexOf("POST", "/v1/auth/kubernetes/login")].body
	failIf(t, login["role"] != "app-secrets-writer" || login["jwt"] != fakeSAToken, "the writer logged in as %v, want the role app-secrets-writer with its service account's token", login)
	for _, value := range []string{"hello-a", "postgres://a", "hello-again", "hello-b"} {
		failIf(t, strings.Contains(out.String(), value), "the writer logged the value %q", value)
	}
}
