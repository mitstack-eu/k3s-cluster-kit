package cluster

// installerscript_test.go runs the verified k3s installer, which copies k3s and install.sh out of images by digest.

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mitstack-eu/block-kit/helpers/tools"
	"github.com/mitstack-eu/block-kit/helpers/tools/toolstest"
	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	fakeInstallSh  = "#!/bin/sh\n# install.sh as the fake tools image holds it\nexit 0\n"
	fakeK3sBinary  = "fake k3s binary bytes\n"
	installerBound = 60 * time.Second
	copyToolPath   = "/usr/local/sbin/mitstack-copy-tool"
)

type installerRun struct {
	output      string
	err         error
	installArgs []string
}

// fakeK3sImages serves Rancher's k3s-upgrade image and the kit's tools image from a fake registry, and the versions pinning them.
type fakeK3sImages struct {
	reg      *toolstest.Registry
	k3s, kit toolstest.Image
	versions Versions
}

func newFakeK3sImages(t *testing.T) fakeK3sImages {
	t.Helper()
	f := fakeK3sImages{reg: toolstest.New(t)}
	f.k3s = f.reg.Push(t, "rancher/k3s-upgrade", toolstest.File{Path: "/opt/k3s", Body: fakeK3sBinary})
	f.kit = f.reg.Push(t, "mitstack-eu/block-kit-tools", toolstest.File{Path: tools.K3sInstaller.Path, Body: fakeInstallSh})
	f.versions = PinnedVersions
	f.versions.K3sImage = f.k3s.Ref
	f.versions.K3sSHA256 = testutil.SHA256Hex(fakeK3sBinary)
	f.versions.K3sInstaller = tools.File{Image: f.kit.Ref, Path: tools.K3sInstaller.Path, SHA256: testutil.SHA256Hex(fakeInstallSh)}
	return f
}

// runInstaller runs the rendered installer beside the rendered copy helper, as /usr/local/sbin holds them, where docker does not run.
func runInstaller(t *testing.T, images fakeK3sImages) installerRun {
	t.Helper()
	in := fixtureRenderInputs()
	in.Versions = images.versions
	cc := testutil.ParseUserData(t, renderOK(t, in))
	sbin, stubs := t.TempDir(), t.TempDir()
	path := testutil.WriteIn(t, sbin, filepath.Base(installerPath), cc.Installer(t).Content, 0o700)
	testutil.WriteIn(t, sbin, filepath.Base(copyToolPath), cc.File(t, copyToolPath).Content, 0o700)
	installArgs := filepath.Join(t.TempDir(), "install-args")
	for _, stub := range []struct{ name, body string }{
		{"uname", "#!/bin/sh\necho x86_64\n"},
		{"install", "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + testutil.ShellQuote(installArgs) + "; done\n"},
		{"docker", "#!/bin/sh\necho 'docker: no container runtime on this machine' >&2\nexit 127\n"},
		{"sleep", "#!/bin/sh\nexit 0\n"},
	} {
		testutil.WriteIn(t, stubs, stub.name, stub.body, 0o755)
	}

	ctx, cancel := context.WithTimeout(context.Background(), installerBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", path)
	tmp := t.TempDir()
	cmd.Env = []string{"PATH=" + stubs + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + tmp, "TMPDIR=" + tmp, images.reg.Env()}
	out, err := cmd.CombinedOutput()
	testutil.FatalIf(t, ctx.Err() != nil, "the installer did not finish within %s:\n%s", installerBound, out)
	run := installerRun{output: string(out), err: err}
	if raw, readErr := os.ReadFile(installArgs); readErr == nil {
		run.installArgs = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	return run
}

func installerLine(v Versions) string {
	return "mitstack-install-k3s: the k3s installer matches SHA-256 " + v.K3sInstaller.SHA256
}

func binaryLine(v Versions) string {
	return "mitstack-install-k3s: the k3s binary " + v.K3sVersion + " matches SHA-256 " + v.K3sSHA256
}

func TestInstaller_ANodeWithNoContainerRuntimeReadsK3sAndInstallShByDigestOverTheRegistrysHTTPAPIAndPrintsEachPinItMatched(t *testing.T) {
	images := newFakeK3sImages(t)

	run := runInstaller(t, images)

	testutil.FatalIf(t, run.err != nil, "the installer over images holding the pinned bytes error = %v; want nil\n%s", run.err, run.output)
	reads := images.reg.Reads()
	for _, img := range []toolstest.Image{images.k3s, images.kit} {
		for _, digest := range append([]string{img.Index, img.Manifest, img.Config}, img.Layers...) {
			testutil.FailIf(t, !slices.Contains(reads, digest), "the registry served the reads %q, want %s among them", reads, digest)
		}
	}
	testutil.FailIf(t, run.installArgs == nil, "the installer never ran install; want it to install the copied k3s\n%s", run.output)
	lines := strings.Split(strings.TrimRight(run.output, "\n"), "\n")
	inst := slices.Index(lines, installerLine(images.versions))
	bin := slices.Index(lines, binaryLine(images.versions))
	testutil.FailIf(t, inst < 0, "the installer printed no line %q; want it\noutput:\n%s", installerLine(images.versions), run.output)
	testutil.FailIf(t, bin < 0, "the installer printed no line %q; want it\noutput:\n%s", binaryLine(images.versions), run.output)
	testutil.FailIf(t, inst >= 0 && bin >= 0 && inst > bin, "the installer printed the binary's match at line %d before the installer's at line %d; want the order it verifies them in", bin, inst)
}

func TestInstaller_AK3sCopyThatFailsInstallsNothingAndNamesTheImage(t *testing.T) {
	for _, c := range []struct {
		name    string
		breakIt func(f *fakeK3sImages)
		says    string
	}{
		{"the layer holds other bytes than the pin", func(f *fakeK3sImages) { f.versions.K3sSHA256 = testutil.SHA256Hex("other bytes") }, "has digest sha256:" + testutil.SHA256Hex(fakeK3sBinary)},
		{"the registry fails the layer read", func(f *fakeK3sImages) { f.reg.Fail(f.k3s.Layers[0], http.StatusNotFound) }, "HTTP 404"},
	} {
		t.Run(c.name, func(t *testing.T) {
			images := newFakeK3sImages(t)
			c.breakIt(&images)

			run := runInstaller(t, images)

			testutil.FatalIf(t, run.err == nil, "the installer where %s error = nil; want a failure:\n%s", c.name, run.output)
			for _, want := range []string{installerLine(images.versions), "could not copy the k3s binary from " + images.versions.K3sImage, c.says} {
				testutil.FailIf(t, !strings.Contains(run.output, want), "the installer where %s printed no %q:\n%s", c.name, want, run.output)
			}
			testutil.FailIf(t, strings.Contains(run.output, "the k3s binary "+images.versions.K3sVersion+" matches"), "the installer printed a match for a binary it could not copy:\n%s", run.output)
			testutil.FailIf(t, run.installArgs != nil, "the installer installed a binary it could not copy, with arguments %q; want install not run", run.installArgs)
		})
	}
}
