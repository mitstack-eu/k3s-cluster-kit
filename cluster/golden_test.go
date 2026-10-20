package cluster

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
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

// renderGoldenSeed leaves out the cluster-bases copies, which their git tree at the release pins instead.
func renderGoldenSeed(t *testing.T) map[string]string {
	t.Helper()
	return testutil.WithoutClusterBases(renderGoldenSeedWithClusterBases(t))
}

func renderGoldenSeedWithClusterBases(t *testing.T) map[string]string {
	t.Helper()
	seed, err := RenderSeed(PinnedVersions, testutil.FixtureIngressIPv4, testutil.FixtureRepoURL)
	testutil.FatalIf(t, err != nil, "RenderSeed: %v", err)
	return seed
}

func TestGolden_UserDataIsByteIdenticalToTheRecordedBytes(t *testing.T) {
	for name, inputs := range goldenUserDataInputs {
		t.Run(name, func(t *testing.T) {
			got := renderOK(t, inputs())
			testutil.AssertSameBytes(t, "the user data", got, testutil.ReadGolden(t, goldenUserDataPath(name)))
		})
	}
}

func TestGolden_SeedIsByteIdenticalToTheRecordedBytes(t *testing.T) {
	seed := renderGoldenSeed(t)
	recorded, err := os.ReadDir(goldenSeedDir())
	testutil.FatalIf(t, err != nil, "listing the recorded seed: %v", err)
	testutil.FailIf(t, len(recorded) != len(seed), "the seed has %d files, the recording has %d", len(seed), len(recorded))
	for file, got := range seed {
		t.Run(file, func(t *testing.T) {
			testutil.AssertSameBytes(t, file, got, testutil.ReadGolden(t, filepath.Join(goldenSeedDir(), path.Base(file))))
		})
	}
}
