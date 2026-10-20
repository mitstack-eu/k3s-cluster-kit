package testutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"go.yaml.in/yaml/v3"
)

func MustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func MapKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func ObjectOf(t *testing.T, what string, raw []byte, keys ...string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	err := json.Unmarshal(raw, &m)
	FatalIf(t, err != nil || m == nil, "%s = %s, want an object of %v", what, Truncate(string(raw), 300), keys)
	got, want := MapKeys(m), slices.Sorted(slices.Values(keys))
	FailIf(t, !slices.Equal(got, want), "%s has keys %v, want exactly %v", what, got, want)
	return m
}

func AssertUTCWithin(t *testing.T, v any, start, end time.Time) {
	t.Helper()
	s, ok := v.(string)
	if !ok || !MadeAtShape.MatchString(s) {
		t.Errorf("time = %#v, want a UTC time written YYYY-MM-DDTHH:MM:SSZ", v)
		return
	}
	at, err := time.Parse(time.RFC3339, s)
	FailIf(t, err != nil || at.Before(start.Truncate(time.Second).Add(-time.Second)) || at.After(end.Add(time.Second)), "time %s (parse err %v) is outside the run, %s to %s", s, err, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

func AssertValues(t *testing.T, what string, got, want map[string]any) {
	t.Helper()
	for k, w := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("%s: missing %s (want %v)", what, k, w)
		} else if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: %s = %#v, want %#v", what, k, g, w)
		}
	}
	for k, g := range got {
		_, ok := want[k]
		FailIf(t, !ok, "%s: unexpected key %s = %#v", what, k, g)
	}
}

func AssertPaths(t *testing.T, what string, doc map[string]any, want map[string]any) {
	t.Helper()
	got := map[string]any{}
	for path := range want {
		got[path] = Dig(doc, strings.Split(path, ".")...)
	}
	AssertValues(t, what, got, want)
}

var CredentialShapes = []string{
	"PRIVATE KEY",
	"client-key",
	"client-certificate",
	"certificate-authority-data",
	"token-auth-file",
	"token-file",
	"agent-token",
	"K3S_TOKEN",
}

func AssertNoCredentialShapes(t *testing.T, what, text string) {
	t.Helper()
	for _, bad := range CredentialShapes {
		FailIf(t, strings.Contains(text, bad), "%s carries %q", what, bad)
	}
	FailIf(t, strings.Contains(strings.ToLower(text), "kubeconfig"), "%s mentions a kubeconfig", what)
}

// ownerKey is a fresh OpenPGP key pair and its armored public half, standing in for the owner's.
func OwnerKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Owner", "", "owner@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	FatalIf(t, err != nil, "generating the owner's key: %v", err)
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	FatalIf(t, err != nil, "armoring the owner's key: %v", err)
	FatalIf(t, e.Serialize(w) != nil || w.Close() != nil, "serializing the owner's key")
	return e, b.String()
}

func DecryptFor(t *testing.T, e *openpgp.Entity, message string) string {
	t.Helper()
	block, err := armor.Decode(strings.NewReader(message))
	FatalIf(t, err != nil || block.Type != "PGP MESSAGE", "%q is not an armored PGP message: %v", message, err)
	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{e}, nil, nil)
	FatalIf(t, err != nil, "the owner's key cannot decrypt the message: %v", err)
	plain, err := io.ReadAll(md.UnverifiedBody)
	FatalIf(t, err != nil, "reading the decrypted message: %v", err)
	return string(plain)
}

func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func AssertNamesAll(t *testing.T, what, text string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		FailIf(t, !strings.Contains(text, needle), "%s does not contain %q", what, needle)
	}
}

var (
	tokenShaped   = regexp.MustCompile(`(^|[^0-9a-f])[0-9a-f]{64}([^0-9a-f]|$)`)
	imageDigests  = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	helmChecksums = regexp.MustCompile(`(?m)^( *checksum/[a-z-]+: )[0-9a-f]{64}$`)
)

// carriesTokenShape reports a 64-hex run that is neither an image digest nor a Helm template checksum, both public content addresses.
func CarriesTokenShape(content string) bool {
	return tokenShaped.MatchString(helmChecksums.ReplaceAllString(imageDigests.ReplaceAllString(content, "sha256:"), "$1"))
}

func ReadGolden(t *testing.T, file string) string {
	t.Helper()
	want, err := os.ReadFile(file)
	FatalIf(t, err != nil, "reading the recorded bytes: %v", err)
	return string(want)
}

func AssertSameBytes(t *testing.T, what, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	t.Errorf("%s differs from the recorded bytes: %d bytes, want %d, first difference at byte %d", what, len(got), len(want), i)
}

func WithoutClusterBases(seed map[string]string) map[string]string {
	kept := map[string]string{}
	for p, content := range seed {
		if !strings.HasPrefix(p, "cluster-bases/") {
			kept[p] = content
		}
	}
	return kept
}

func FailIf(t *testing.T, bad bool, format string, args ...any) {
	t.Helper()
	if bad {
		t.Errorf(format, args...)
	}
}

func FatalIf(t *testing.T, bad bool, format string, args ...any) {
	t.Helper()
	if bad {
		t.Fatalf(format, args...)
	}
}

func CIJobs(t *testing.T, workflowPath string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	FatalIf(t, err != nil, "reading the CI workflow: %v", err)
	var workflow map[string]any
	FatalIf(t, yaml.Unmarshal(raw, &workflow) != nil, "the CI workflow is not YAML")
	jobs, ok := workflow["jobs"].(map[string]any)
	FatalIf(t, !ok, "the CI workflow has no jobs mapping")
	return jobs
}

// JobUsesAndRuns lists a job's step actions and run scripts, each in step order.
func JobUsesAndRuns(t *testing.T, name string, job map[string]any) (uses, runs []string) {
	t.Helper()
	steps, ok := job["steps"].([]any)
	FatalIf(t, !ok, "%s steps = %#v, want a list", name, job["steps"])
	for _, s := range steps {
		step := s.(map[string]any)
		if u, ok := step["uses"].(string); ok {
			uses = append(uses, u)
		}
		if r, ok := step["run"].(string); ok {
			runs = append(runs, r)
		}
	}
	return uses, runs
}
