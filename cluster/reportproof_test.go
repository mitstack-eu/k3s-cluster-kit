package cluster

// The report signs the exact body it posts with the proof script its pod carries, and posts unsigned when it cannot.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/block-kit/helpers/reportproof"
	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const mintedProof = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiZml4dHVyZSJdfQ.c2lnbmF0dXJl"

func TestReportProof_SignsTheBodyItPosts(t *testing.T) {
	runReportCases(t, []reportCase{
		{name: "sends what the proof script prints for the posted body as Mitstack-Report-Proof", check: func(t *testing.T, r *reportRig) {
			args, body := r.proof.ran(t)
			testutil.FailIf(t, r.req.ReportProof != "report-proof-fixture", "Mitstack-Report-Proof = %q, want report-proof-fixture, what the proof script printed", r.req.ReportProof)
			testutil.FailIf(t, !bytes.Equal(body, r.req.Body), "the proof script was given %d bytes of body, want the %d bytes posted", len(body), len(r.req.Body))
			testutil.FatalIf(t, len(args) != 5, "the proof script ran with %q, want its name and four arguments", args)
			want := []string{"token-request.sh", r.srv.URL + testutil.ReportEndpointPath, "mitstack-node", "mitstack-node-report"}
			got := append([]string{args[0]}, args[2:]...)
			testutil.FailIf(t, !slices.Equal(got, want), "the proof script ran as %q with the URL, namespace and account %q, want %q", args[0], args[2:], want)
		}},
		{name: "runs block-kit's token request for a token naming the platform's origin and the posted body's digest",
			opts: []reportOption{withEnvVar(reportProofScriptEnv, reportproof.TokenRequestScript), withK3s(k3sMintingToken(mintedProof))}, check: func(t *testing.T, r *reportRig) {
				testutil.FailIf(t, r.req.ReportProof != mintedProof, "Mitstack-Report-Proof = %q, want %q, the token the API server minted", r.req.ReportProof, mintedProof)
				sum := sha256.Sum256(r.req.Body)
				want := []string{"kubectl", "create", "token", "mitstack-node-report", "-n", "mitstack-node",
					"--audience", r.srv.URL, "--audience", "report-sha256:" + hex.EncodeToString(sum[:]), "--duration", "10m"}
				i := slices.IndexFunc(r.k3s.argvs(t), func(argv []string) bool { return len(argv) > 2 && argv[1] == "create" && argv[2] == "token" })
				testutil.FatalIf(t, i < 0, "the report asked the API server for no token")
				testutil.FailIf(t, !slices.Equal(r.k3s.argvs(t)[i], want), "the token request ran %q\nwant                   %q", r.k3s.argvs(t)[i], want)
			}},
	})
}

func TestReportProof_PostsUnsignedAndExitsNonZeroWhenTheProofFails(t *testing.T) {
	var cases []reportCase
	for name, opt := range map[string]reportOption{
		"the proof script fails":          withProofAnswer("echo 'error: serviceaccounts \"mitstack-node-report\" is forbidden' >&2; exit 1"),
		"the proof script prints nothing": withProofAnswer("true"),
		"the proof script prints a second line, which would become a header of its own": withProofAnswer("printf 'report-proof-fixture\\nX-Injected: yes\\n'"),
		"the pod carries no proof script":                                               withEnvVar(reportProofScriptEnv, ""),
	} {
		cases = append(cases, reportCase{name: name, opts: []reportOption{opt}, manual: true, check: func(t *testing.T, r *reportRig) {
			assertExitedNonZero(t, name, r.exec())
			reqs := r.srv.Received()
			testutil.FatalIf(t, len(reqs) != 1, "the report script sent %d reports when %s, want exactly one, unsigned", len(reqs), name)
			testutil.FailIf(t, reqs[0].ReportProof != "", "the report carries Mitstack-Report-Proof %q when %s, want none", reqs[0].ReportProof, name)
			testutil.FailIf(t, !strings.Contains(r.run.Stderr, "unsigned"), "the report script's stderr does not say the report went unsigned:\n%s", r.run.Stderr)
		}})
	}
	runReportCases(t, cases)
}
