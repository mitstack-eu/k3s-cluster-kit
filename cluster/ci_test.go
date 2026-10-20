package cluster

// ci_test.go holds the module's CI workflow to running the Kyverno policy tests and the k3s proofs before a release.

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	kyvernoCLIURL    = "https://github.com/kyverno/kyverno/releases/download/v1.19.1/kyverno-cli_v1.19.1_linux_x86_64.tar.gz"
	kyvernoCLISHA256 = "b38228f367fc0fdc2b08f4c83ea50ac5f16c60ff8d62d76a66157c33c47b70ae"
	checkoutPin      = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	ubicloudRunsOn   = `${{ fromJSON(vars.CI_RUNS_ON || '["ubicloud-standard-2"]') }}`
	workflowPath     = "../.github/workflows/ci.yml"
)

func kyvernoTestJob(t *testing.T) map[string]any {
	t.Helper()
	job, ok := testutil.CIJobs(t, workflowPath)["kyverno-test"].(map[string]any)
	testutil.FatalIf(t, !ok, "the CI workflow has no job kyverno-test")
	return job
}

func TestCI_KyvernoTestJobRunsOnUbicloud(t *testing.T) {
	job := kyvernoTestJob(t)

	testutil.FailIf(t, job["runs-on"] != ubicloudRunsOn, "kyverno-test runs-on = %#v, want %q: Ubicloud is the only sanctioned runner", job["runs-on"], ubicloudRunsOn)
}

func TestCI_KyvernoTestJobChecksOutThePinnedActionAndRunsTheCLIAtV1191AfterCheckingItsDigest(t *testing.T) {
	uses, runs := testutil.JobUsesAndRuns(t, "kyverno-test", kyvernoTestJob(t))
	script := strings.Join(runs, "\n")

	testutil.FailIf(t, len(uses) != 1 || !strings.HasPrefix(uses[0], checkoutPin), "kyverno-test uses %q, want exactly %s, pinned as the operator kit's publish-block workflow pins it", uses, checkoutPin)
	testutil.FailIf(t, !strings.Contains(script, kyvernoCLIURL), "kyverno-test downloads no %s", kyvernoCLIURL)
	testutil.FailIf(t, !strings.Contains(script, kyvernoCLISHA256) || !strings.Contains(script, "sha256sum"), "kyverno-test does not check the download against sha256 %s", kyvernoCLISHA256)
	testutil.FailIf(t, !strings.Contains(script, "kyverno test admission/tests"), "kyverno-test never runs `kyverno test admission/tests`")
	testutil.FailIf(t, strings.Index(script, "sha256sum") > strings.Index(script, "kyverno test admission/tests"), "kyverno-test runs the CLI before it checks the download's sha256")
}

// k3sProofs are the jobs that prove on a running k3s node what the seed and the user data's bytes do, and the script each runs.
var k3sProofs = map[string]string{
	"localpv-lvm":      "sudo scripts/ci/localpv-lvm-proof.sh",
	"openbao-boot":     "sudo scripts/ci/openbao-boot-proof.sh",
	"node-agent-reads": "sudo scripts/ci/node-agent-proof.sh",
}

func TestCI_EachK3sProofJobRunsItsProofAsRootOnUbicloud(t *testing.T) {
	for name, script := range k3sProofs {
		t.Run(name, func(t *testing.T) {
			job, ok := testutil.CIJobs(t, workflowPath)[name].(map[string]any)
			testutil.FatalIf(t, !ok, "the CI workflow has no job %s", name)
			testutil.FailIf(t, job["runs-on"] != ubicloudRunsOn, "%s runs-on = %#v, want %q: Ubicloud is the only sanctioned runner", name, job["runs-on"], ubicloudRunsOn)

			uses, runs := testutil.JobUsesAndRuns(t, name, job)

			testutil.FailIf(t, len(uses) != 1 || !strings.HasPrefix(uses[0], checkoutPin), "%s uses %q, want exactly %s", name, uses, checkoutPin)
			testutil.FailIf(t, !slices.Contains(runs, script), "%s runs %q, want `%s`, since the proof installs k3s", name, runs, script)
		})
	}
}

func TestCI_ReleaseWaitsForTheSuitesThePolicyTestsAndEachK3sProof(t *testing.T) {
	release, ok := testutil.CIJobs(t, workflowPath)["release"].(map[string]any)
	testutil.FatalIf(t, !ok, "the CI workflow has no job release")
	var needs []string
	for _, n := range release["needs"].([]any) {
		needs = append(needs, n.(string))
	}

	for _, name := range append([]string{"test", "kyverno-test"}, slices.Sorted(maps.Keys(k3sProofs))...) {
		testutil.FailIf(t, !slices.Contains(needs, name), "release needs %v, want %s among them, so no tag names a commit that failed it", needs, name)
	}
	testutil.FailIf(t, release["if"] != "github.event_name == 'push' && github.ref == 'refs/heads/main'", "release runs if %v, want on a push to main alone", release["if"])
}
