package cluster

// refusalreason_test.go pins how the enrol and refresh scripts print the platform's refusal reason.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const (
	enrolRefusalPrefix   = "mitstack-enrol: the platform refused the enrolment with HTTP "
	refreshRefusalPrefix = "mitstack-repo-token: the platform refused the repository token with HTTP "

	refusalReasonLimit = 500
)

const literalEscapes = `refused \033[31mRED\033[0m then \nfake-line\c cut-tail`

const realControls = "refused\x1b[31m RED\r\nfake-line\tmore\x07 tail-end"

const unicodeControls = "refusé über\u009b31m\u0085next line para‮evil tail-end"

var longReason = "GitHub said: " + strings.Repeat("abcdefghij", 200)[:2000-len("GitHub said: ")]

type refusalCase struct {
	name, errorText string
	check           func(t *testing.T, reason string)
}

var refusalCases = []refusalCase{
	{
		name: "a plain reason", errorText: githubRefusal,
		check: func(t *testing.T, reason string) {
			failIf(t, reason != githubRefusal, "the reason printed is %q, want the platform's error %q", reason, githubRefusal)
		},
	},
	{
		name: "literal backslash escapes", errorText: literalEscapes,
		check: func(t *testing.T, reason string) {
			// Backslashes may be kept or dropped, but the text around them
			// must arrive whole, nothing cut after \c.
			want := strings.ReplaceAll(literalEscapes, `\`, "")
			got := strings.ReplaceAll(reason, `\`, "")
			failIf(t, got != want, "the reason printed is %q, want %q with its backslashes kept or dropped and never interpreted", reason, literalEscapes)
		},
	},
	{
		name: "real control characters", errorText: realControls,
		check: func(t *testing.T, reason string) {
			for _, part := range []string{"refused", "[31m RED", "fake-line", "more", "tail-end"} {
				failIf(t, !strings.Contains(reason, part), "the reason printed is %q, want the printable text %q of the error kept", reason, part)
			}
		},
	},
	{
		name: "unicode controls and separators", errorText: unicodeControls,
		check: func(t *testing.T, reason string) {
			for _, part := range []string{"refusé", "über", "31m", "next", "line", "para", "evil", "tail-end"} {
				failIf(t, !strings.Contains(reason, part), "the reason printed is %q, want the printable text %q of the error kept", reason, part)
			}
			for _, r := range reason {
				failIf(t, unprintable(r), "the reason printed carries the unprintable character %U: %q", r, reason)
			}
		},
	},
	{
		name: "a 2000-character reason", errorText: longReason,
		check: func(t *testing.T, reason string) {
			n := utf8.RuneCountInString(reason)
			failIf(t, n == 0 || n > refusalReasonLimit, "the reason printed is %d characters, want 1 to %d", n, refusalReasonLimit)
			failIf(t, !strings.HasPrefix(longReason, reason), "the reason printed is not the start of the platform's error: %q", truncate(reason, 80))
		},
	},
}

func errorBody(t *testing.T, text string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"error": text})
	fatalIf(t, err != nil, "encoding the error body: %v", err)
	return string(raw) + "\n"
}

func unprintable(r rune) bool {
	if r == ' ' {
		return false
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs)
}

func assertCleanStderr(t *testing.T, who, stderr string) {
	t.Helper()
	for i, r := range stderr {
		if r != '\n' && unprintable(r) {
			t.Errorf("%s's stderr carries the unprintable character %U at byte %d:\n%q", who, r, i, stderr)
			break
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		failIf(t, line != "" && !strings.HasPrefix(line, who+":"), "%s's stderr carries a line it did not start, %q:\n%q", who, line, stderr)
	}
}

func refusalReason(t *testing.T, stderr, prefix string, status int) string {
	t.Helper()
	head := prefix + strconv.Itoa(status)
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.HasPrefix(line, head) {
			continue
		}
		reason, ok := strings.CutPrefix(line, head+": ")
		fatalIf(t, !ok, "the refusal line carries no \": <reason>\" after HTTP %d: %q", status, line)
		return reason
	}
	t.Fatalf("no line of stderr starts %q:\n%q", head, stderr)
	return ""
}

func TestEnrolScript_A4xxReasonReachesStderrAsSanitisedText(t *testing.T) {
	t.Parallel()
	for _, tc := range refusalCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			script, env := renderedEnrolment(t)
			srv := newFakeEnrolment(t, fixtureEnrolmentToken, http.StatusFailedDependency)
			srv.answerStatusWith(http.StatusFailedDependency, errorBody(t, tc.errorText))
			why := "a 424 with " + tc.name

			run := runEnrolScript(t, script.Content, env, srv.endpoint(), srv.caFile, enrolRefusalBound)

			assertExitedNonZero(t, why, run)
			assertNoEnrolmentJSON(t, why, run)
			n := len(srv.received())
			failIf(t, n != 1, "the enrol script sent %d requests on %s, want exactly one", n, why)
			assertCleanStderr(t, "mitstack-enrol", run.stderr)
			tc.check(t, refusalReason(t, run.stderr, enrolRefusalPrefix, http.StatusFailedDependency))
		})
	}
}

func TestRepoTokenScript_A4xxNamesTheStatusAndTheSanitisedReasonAndPatchesNothing(t *testing.T) {
	t.Parallel()
	cases := append([]refusalCase(nil), refusalCases...)
	cases = append(cases, refusalCase{
		name: "an unknown report token answered 401", errorText: "unknown report token",
		check: func(t *testing.T, reason string) {
			failIf(t, reason != "unknown report token", "the reason printed is %q, want the platform's error", reason)
		},
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status := http.StatusFailedDependency
			if strings.Contains(tc.name, "401") {
				status = http.StatusUnauthorized
			}
			why := "a " + strconv.Itoa(status) + " with " + tc.name

			r := runRefresh(t, fixtureReportToken, []int{status}, errorBody(t, tc.errorText))

			r.refused(t, why, 1)
			assertCleanStderr(t, "mitstack-repo-token", r.run.stderr)
			tc.check(t, refusalReason(t, r.run.stderr, refreshRefusalPrefix, status))
		})
	}
	t.Run("a body that is not JSON", func(t *testing.T) {
		t.Parallel()
		r := runRefresh(t, fixtureReportToken, []int{http.StatusFailedDependency}, "<html>Failed Dependency</html>\n")

		r.refused(t, "a 424 that is not JSON", 1)
		assertCleanStderr(t, "mitstack-repo-token", r.run.stderr)
		failIf(t, !strings.Contains(r.run.stderr, refreshRefusalPrefix+"424"), "on a 424 that is not JSON the refresh's stderr does not start %q:\n%s", refreshRefusalPrefix+"424", r.run.stderr)
	})
}

func TestRepoTokenScript_ABusyOrUnreachableEndpointPrintsTheStatus(t *testing.T) {
	t.Parallel()
	t.Run("503", func(t *testing.T) {
		t.Parallel()
		r := runRefresh(t, fixtureReportToken, []int{http.StatusServiceUnavailable}, "")

		assertExitedNonZero(t, "a 503", r.run)
		failIf(t, !strings.Contains(r.run.stderr, "HTTP 503"), "the refresh's stderr on a 503 = %q; want it to name HTTP 503", r.run.stderr)
	})
	t.Run("connection failure", func(t *testing.T) {
		t.Parallel()
		r := runRefresh(t, fixtureReportToken, nil, "")

		assertExitedNonZero(t, "a connection failure", r.run)
		failIf(t, !strings.Contains(r.run.stderr, "mitstack-repo-token: "), "on a connection failure the refresh printed no line of its own:\n%s", r.run.stderr)
	})
}
