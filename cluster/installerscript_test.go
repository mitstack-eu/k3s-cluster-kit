package cluster

// installerscript_test.go runs the verified k3s installer script.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	fakeInstallSh  = "#!/bin/sh\n# install.sh as the fake curl serves it\nexit 0\n"
	fakeK3sBinary  = "fake k3s binary bytes\n"
	installerBound = 30 * time.Second
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type installerRun struct {
	output      string
	err         error
	installArgs []string
}

func runInstaller(t *testing.T, v Versions) installerRun {
	t.Helper()
	in := fixtureRenderInputs()
	in.Versions = v
	ud := renderOK(t, in)
	script := parseUserData(t, ud).installer(t).Content

	stubs := t.TempDir()
	served := t.TempDir()
	installArgs := filepath.Join(t.TempDir(), "install-args")
	for _, f := range []struct{ name, content string }{{"install.sh", fakeInstallSh}, {"k3s", fakeK3sBinary}} {
		err := os.WriteFile(filepath.Join(served, f.name), []byte(f.content), 0o600)
		fatalIf(t, err != nil, "writing the served %s error = %v; want nil", f.name, err)
	}
	for _, stub := range []struct{ name, body string }{
		{"uname", "#!/bin/sh\necho x86_64\n"},
		{"install", "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + shQuote(installArgs) + "; done\n"},
		{"curl", "#!/bin/sh\n" +
			"out= url= prev=\n" +
			"for a in \"$@\"; do\n" +
			"  case $prev in --output | -o) out=$a ;; esac\n" +
			"  prev=$a\n" +
			"  url=$a\n" +
			"done\n" +
			"case $url in\n" +
			"  */install.sh) exec cp " + shQuote(filepath.Join(served, "install.sh")) + " \"$out\" ;;\n" +
			"  */k3s) exec cp " + shQuote(filepath.Join(served, "k3s")) + " \"$out\" ;;\n" +
			"esac\n" +
			"echo \"fake curl: no answer for $url\" >&2\n" +
			"exit 22\n"},
	} {
		err := os.WriteFile(filepath.Join(stubs, stub.name), []byte(stub.body), 0o755)
		fatalIf(t, err != nil, "writing the %s stub error = %v; want nil", stub.name, err)
	}
	path := filepath.Join(t.TempDir(), "install-k3s.sh")
	err := os.WriteFile(path, []byte(script), 0o700)
	fatalIf(t, err != nil, "writing the installer error = %v; want nil", err)

	ctx, cancel := context.WithTimeout(context.Background(), installerBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", path)
	tmp := t.TempDir()
	cmd.Env = []string{"PATH=" + stubs + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + tmp, "TMPDIR=" + tmp}
	out, err := cmd.CombinedOutput()
	fatalIf(t, ctx.Err() != nil, "the installer did not finish within %s:\n%s", installerBound, out)
	run := installerRun{output: string(out), err: err}
	if raw, readErr := os.ReadFile(installArgs); readErr == nil {
		run.installArgs = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	return run
}

func stubbedVersions() Versions {
	v := PinnedVersions
	v.K3sInstallerSHA256 = sha256Hex(fakeInstallSh)
	v.K3sSHA256 = sha256Hex(fakeK3sBinary)
	return v
}

func installerLine(v Versions) string {
	return "mitstack-install-k3s: the k3s installer matches SHA-256 " + v.K3sInstallerSHA256
}

func binaryLine(v Versions) string {
	return "mitstack-install-k3s: the k3s binary " + v.K3sVersion + " matches SHA-256 " + v.K3sSHA256
}

func TestInstaller_PrintsEachVerifiedArtifactAndThePinnedDigestItMatched(t *testing.T) {
	v := stubbedVersions()

	run := runInstaller(t, v)

	fatalIf(t, run.err != nil, "the installer over bytes that match their pins error = %v; want nil\n%s", run.err, run.output)
	lines := strings.Split(strings.TrimRight(run.output, "\n"), "\n")
	inst := slices.Index(lines, installerLine(v))
	bin := slices.Index(lines, binaryLine(v))
	failIf(t, inst < 0, "the installer printed no line %q; want it\noutput:\n%s", installerLine(v), run.output)
	failIf(t, bin < 0, "the installer printed no line %q; want it\noutput:\n%s", binaryLine(v), run.output)
	failIf(t, inst >= 0 && bin >= 0 && inst > bin, "the installer printed the binary's match at line %d before the installer's at line %d; want the order it verifies them in", bin, inst)
	failIf(t, run.installArgs == nil, "the installer never ran install; want it to install the verified binary")
}

func TestInstaller_PrintsNoMatchForAnArtifactThatFailsItsDigest(t *testing.T) {
	v := stubbedVersions()
	v.K3sSHA256 = sha256Hex("other bytes than the fake curl serves")

	run := runInstaller(t, v)

	fatalIf(t, run.err == nil, "the installer over a binary that does not match its pin error = nil; want a failure:\n%s", run.output)
	failIf(t, !strings.Contains(run.output, installerLine(v)), "the installer printed no line %q before the binary failed; want it:\n%s", installerLine(v), run.output)
	failIf(t, strings.Contains(run.output, "the k3s binary "+v.K3sVersion+" matches"), "the installer printed a match for a binary that failed its digest; want none:\n%s", run.output)
	failIf(t, run.installArgs != nil, "the installer installed a binary that failed its digest, with arguments %q; want install not run", run.installArgs)
}
