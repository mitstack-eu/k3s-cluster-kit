package cluster

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// goldenUserDataInputs' hosts-platform recording is also what scripts/ci/openbao-boot-proof.sh boots.
var goldenUserDataInputs = map[string]func() UserDataInputs{
	"fixture":        fixtureRenderInputs,
	"longest":        longestRenderInputs,
	"hosts-platform": hostsPlatformRenderInputs,
}

func goldenUserDataPath(name string) string {
	return filepath.Join("testdata", "golden", "userdata-"+name+".yaml")
}

func goldenSeedDir() string { return filepath.Join("testdata", "golden", "seed") }

func readGolden(t *testing.T, file string) string {
	t.Helper()
	want, err := os.ReadFile(file)
	fatalIf(t, err != nil, "reading the recorded bytes: %v", err)
	return string(want)
}

func assertSameBytes(t *testing.T, what, got, want string) {
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

// renderGoldenSeed leaves out the cluster-bases copies, which their git tree at the release pins instead.
func renderGoldenSeed(t *testing.T) map[string]string {
	t.Helper()
	return withoutClusterBases(renderGoldenSeedWithClusterBases(t))
}

func renderGoldenSeedWithClusterBases(t *testing.T) map[string]string {
	t.Helper()
	seed, err := RenderSeed(PinnedVersions, fixtureIngressIPv4, fixtureRepoURL)
	fatalIf(t, err != nil, "RenderSeed: %v", err)
	return seed
}

func withoutClusterBases(seed map[string]string) map[string]string {
	kept := map[string]string{}
	for p, content := range seed {
		if !strings.HasPrefix(p, "cluster-bases/") {
			kept[p] = content
		}
	}
	return kept
}

func TestGolden_UserDataIsByteIdenticalToTheRecordedBytes(t *testing.T) {
	for name, inputs := range goldenUserDataInputs {
		t.Run(name, func(t *testing.T) {
			got := renderOK(t, inputs())
			assertSameBytes(t, "the user data", got, readGolden(t, goldenUserDataPath(name)))
		})
	}
}

func TestGolden_SeedIsByteIdenticalToTheRecordedBytes(t *testing.T) {
	seed := renderGoldenSeed(t)
	recorded, err := os.ReadDir(goldenSeedDir())
	fatalIf(t, err != nil, "listing the recorded seed: %v", err)
	failIf(t, len(recorded) != len(seed), "the seed has %d files, the recording has %d", len(seed), len(recorded))
	for file, got := range seed {
		t.Run(file, func(t *testing.T) {
			assertSameBytes(t, file, got, readGolden(t, filepath.Join(goldenSeedDir(), path.Base(file))))
		})
	}
}
