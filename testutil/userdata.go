package testutil

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// bootDocs maps each file in k3s's auto-deploy directory to the documents it holds.
func BootDocs(t *testing.T, cc CloudConfig) map[string][]map[string]any {
	t.Helper()
	docs := map[string][]map[string]any{}
	for _, f := range cc.WriteFiles {
		if path.Dir(f.Path) == BootDir && strings.HasSuffix(f.Path, ".yaml") {
			docs[path.Base(f.Path)] = YamlDocs(t, f.Path, f.Content)
		}
	}
	return docs
}

// onlyDoc finds the one document of a kind and name, and the file that holds it.
func OnlyDoc(t *testing.T, docs map[string][]map[string]any, kind, name string) (string, map[string]any) {
	t.Helper()
	var file string
	var found []map[string]any
	for f, list := range docs {
		for _, d := range list {
			if d["kind"] == kind && Dig(d, "metadata", "name") == name {
				file, found = f, append(found, d)
			}
		}
	}
	FatalIf(t, len(found) != 1, "the auto-deploy directory holds %d %s %s, want exactly one", len(found), kind, name)
	return file, found[0]
}

// sealKeyOf reads the seal key a node's user data writes.
func SealKeyOf(t *testing.T, cc CloudConfig) string {
	t.Helper()
	f := cc.File(t, SealKeyFile)
	_, secret := OnlyDoc(t, map[string][]map[string]any{path.Base(f.Path): YamlDocs(t, f.Path, f.Content)}, "Secret", "openbao-seal-key")
	key, _ := Dig(secret, "stringData", "key").(string)
	FatalIf(t, !HexSealKey.MatchString(key), "the seal key is %d characters, want 64 hex", len(key))
	return key
}

func ChartValues(t *testing.T, what string, app map[string]any) map[string]any {
	t.Helper()
	values, ok := Dig(app, "spec", "source", "helm", "values").(string)
	FatalIf(t, !ok, "%s spec.source.helm.values is %T, want the values text", what, Dig(app, "spec", "source", "helm", "values"))
	return YamlMap(t, what+" helm.values", values)
}

type CloudFile struct {
	Path        string `yaml:"path"`
	Content     string `yaml:"content"`
	Permissions string `yaml:"permissions"`
	Owner       string `yaml:"owner"`
	Encoding    string `yaml:"encoding"`
	Defer       bool   `yaml:"defer"`
}

type CloudConfig struct {
	WriteFiles []CloudFile `yaml:"write_files"`
	RunCmd     []any       `yaml:"runcmd"`
}

func ParseUserData(t *testing.T, userData string) CloudConfig {
	t.Helper()
	FatalIf(t, !strings.HasPrefix(userData, "#cloud-config\n"), "the user data must start with a #cloud-config line, starts with %q", FirstLine(userData))
	var cc CloudConfig
	err := yaml.Unmarshal([]byte(userData), &cc)
	FatalIf(t, err != nil, "the user data is not valid YAML: %v", err)
	for i := range cc.WriteFiles {
		cc.WriteFiles[i].Content = DecodeContent(t, cc.WriteFiles[i])
	}
	return cc
}

func FirstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func DecodeContent(t *testing.T, f CloudFile) string {
	t.Helper()
	unbase64 := func() []byte {
		clean := strings.Join(strings.Fields(f.Content), "")
		raw, err := base64.StdEncoding.DecodeString(clean)
		FatalIf(t, err != nil, "%s: content declared %q is not base64: %v", f.Path, f.Encoding, err)
		return raw
	}
	switch strings.ToLower(f.Encoding) {
	case "", "text/plain":
		return f.Content
	case "b64", "base64":
		return string(unbase64())
	case "gz+b64", "gz+base64", "gzip+b64", "gzip+base64":
		zr, err := gzip.NewReader(bytes.NewReader(unbase64()))
		FatalIf(t, err != nil, "%s: content declared %q is not gzip: %v", f.Path, f.Encoding, err)
		raw, err := io.ReadAll(zr)
		FatalIf(t, err != nil, "%s: reading gzip content: %v", f.Path, err)
		return string(raw)
	default:
		t.Fatalf("%s: unsupported write_files encoding %q", f.Path, f.Encoding)
		return ""
	}
}

func (cc CloudConfig) File(t *testing.T, path string) CloudFile {
	t.Helper()
	var found []CloudFile
	for _, f := range cc.WriteFiles {
		if f.Path == path {
			found = append(found, f)
		}
	}
	FatalIf(t, len(found) != 1, "want exactly one write_files entry at %s, found %d", path, len(found))
	return found[0]
}

func (cc CloudConfig) onlyFileWhere(t *testing.T, what string, match func(CloudFile) bool) CloudFile {
	t.Helper()
	var found []CloudFile
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

func (cc CloudConfig) NodeScript(t *testing.T) CloudFile {
	t.Helper()
	return cc.onlyFileWhere(t, "the node script (reads hetzner/v1/metadata)", func(f CloudFile) bool {
		return strings.Contains(f.Content, "hetzner/v1/metadata")
	})
}

func (cc CloudConfig) Installer(t *testing.T) CloudFile {
	t.Helper()
	return cc.onlyFileWhere(t, "the verified installer (downloads k3s-io/k3s install.sh)", func(f CloudFile) bool {
		return strings.Contains(f.Content, "raw.githubusercontent.com/k3s-io/k3s/")
	})
}

func (cc CloudConfig) EnrolScript(t *testing.T) CloudFile {
	t.Helper()
	// The report script names cluster-enrolments too, for its one-time reuse
	// probe, so the enrol script is the one that does not post reports.
	return cc.onlyFileWhere(t, "the enrol script (posts to cluster-enrolments)", func(f CloudFile) bool {
		return strings.Contains(f.Content, "cluster-enrolments") && !strings.Contains(f.Content, "cluster-reports")
	})
}

func (cc CloudConfig) RuncmdText() string {
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

func YamlDocs(t *testing.T, what, content string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(content))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		FatalIf(t, err != nil, "%s is not valid YAML: %v", what, err)
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

func YamlMap(t *testing.T, what, content string) map[string]any {
	t.Helper()
	docs := YamlDocs(t, what, content)
	FatalIf(t, len(docs) != 1, "%s: want one YAML document, found %d", what, len(docs))
	return docs[0]
}

func Dig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func EnrolmentEnv(t *testing.T, cc CloudConfig) map[string]string {
	t.Helper()
	f := cc.File(t, "/etc/mitstack/enrolment.env")
	env := map[string]string{}
	for _, line := range strings.Split(f.Content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		FatalIf(t, !ok, "enrolment.env line %q is not KEY=VALUE", line)
		env[k] = strings.Trim(v, `"'`)
	}
	return env
}

func (cc CloudConfig) AllText(raw string) string {
	var b strings.Builder
	b.WriteString(raw)
	for _, f := range cc.WriteFiles {
		b.WriteString("\n")
		b.WriteString(f.Content)
	}
	b.WriteString("\n")
	b.WriteString(cc.RuncmdText())
	return b.String()
}
