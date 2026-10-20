package cluster

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func assertVerdict(t *testing.T, run patchCheckRun, verdict string) {
	t.Helper()
	got := run.result["verdict"]
	failIf(t, got != verdict, "%s verdict = %#v, want %q:\n%s", patchCheckFile, got, verdict, run.raw)
	wantExit := 1
	if verdict == "pass" {
		wantExit = 0
	}
	failIf(t, run.exit != wantExit, "the patch check exited %d with verdict %q, want %d:\n%s", run.exit, verdict, wantExit, run.output())
	summary := strings.TrimRight(run.stdout, "\n")
	if summary == "" || strings.Contains(summary, "\n") {
		t.Errorf("the patch check printed %q on stdout, want a one-line summary", run.stdout)
	} else if !strings.Contains(summary, verdict) {
		t.Errorf("the patch check's summary %q does not name its verdict %q", summary, verdict)
	}
}

func assertResultShape(t *testing.T, run patchCheckRun, now string) {
	t.Helper()
	keys := mapKeys(run.result)
	failIf(t, !slices.Equal(keys, []string{"checkedAt", "k3s", "maxBehindDays", "os", "verdict"}), "%s has keys %v, want exactly checkedAt, verdict, maxBehindDays, os and k3s", patchCheckFile, keys)
	failIf(t, now != "" && run.result["checkedAt"] != now, "%s checkedAt = %#v, want the clock's %s", patchCheckFile, run.result["checkedAt"], now)
	got := run.result["maxBehindDays"]
	failIf(t, got != float64(patchCheckMaxBehindDays), "%s maxBehindDays = %#v, want %d", patchCheckFile, got, patchCheckMaxBehindDays)
}

func wantK3s(running, latest string, firstNewer, publishedAt any, behindDays int, verdict string) map[string]any {
	channel := strings.Join(strings.SplitN(strings.TrimPrefix(running, "v"), ".", 3)[:2], ".")
	return map[string]any{
		"running": running, "channel": "v" + channel, "latest": latest,
		"firstNewer": firstNewer, "firstNewerPublishedAt": publishedAt,
		"behindDays": float64(behindDays), "verdict": verdict,
	}
}

func wantPatchedOS(refreshedAt string) map[string]any {
	return map[string]any{
		"running": runningOS, "latestKernel": runningKernel, "pendingUpgrades": []any{},
		"rebootRequired": false, "listsRefreshedAt": refreshedAt,
		"behindSince": nil, "behindDays": float64(0), "verdict": "pass",
	}
}

var wantAptPending = []any{
	map[string]any{"package": "libssl3t64", "installed": "3.0.13-0ubuntu3.5", "candidate": "3.0.13-0ubuntu3.6"},
	map[string]any{"package": "openssl", "installed": "3.0.13-0ubuntu3.5", "candidate": "3.0.13-0ubuntu3.6"},
	map[string]any{"package": "linux-image-6.8.0-85-generic", "installed": nil, "candidate": "6.8.0-85.85"},
}

func TestPatchCheck_DefaultsToTheNodesSourcesAndTheK3sReleaseFeeds(t *testing.T) {
	body := testRepoFile(t, "scripts/mitstack-patch-check.sh")
	for _, needle := range []string{
		"https://update.k3s.io/v1-release/channels",
		"https://api.github.com/repos/k3s-io/k3s/releases",
		"per_page=100",
		"/var/lib/mitstack",
		patchCheckFile,
		"/boot",
		"/etc/os-release",
		"/var/run/reboot-required",
		"dist-upgrade",
		"/usr/local/bin/k3s",
		reportK3sEnv, patchCheckAptGetEnv, patchCheckUnameEnv, reportOSReleaseEnv, patchCheckBootDirEnv,
		reportStateDirEnv, reportRebootRequiredEnv, patchCheckChannelsURLEnv, patchCheckReleasesURLEnv, patchCheckNowEnv,
		patchCheckUpdateStampEnv, aptUpdateStampDefault,
	} {
		failIf(t, !strings.Contains(body, needle), "the patch check does not contain %q", needle)
	}
}

func TestPatchCheck_K3sVerdictFollowsHowManyWholeDaysBehindItsChannelItIs(t *testing.T) {
	const published, latest = "2026-09-30T01:12:40Z", "v1.36.5+k3s1"
	for _, tc := range []struct {
		name, running, now string
		firstNewer         any
		publishedAt        any
		days               int
		verdict            string
	}{
		{"more than 14 days behind fails and the oldest newer release is not a prerelease", "v1.36.3+k3s1", "2026-10-07T18:00:00Z", "v1.36.4+k3s1", "2026-08-27T15:53:55Z", 41, "fail"},
		{"a first newer release 8 days old passes", "v1.36.4+k3s1", "2026-10-08T03:10:00Z", latest, published, 8, "pass"},
		{"the channel's latest is 0 days behind, whatever newer prereleases and minors exist", latest, "2026-10-08T03:10:00Z", nil, nil, 0, "pass"},
		{"14 days and 23 hours still passes", "v1.36.4+k3s1", "2026-10-14T03:00:00Z", latest, published, 14, "pass"},
		{"14 days and 0 hours still passes", "v1.36.4+k3s1", "2026-10-15T01:00:00Z", latest, published, 14, "pass"},
		{"the fifteenth whole day fails", "v1.36.4+k3s1", "2026-10-15T03:00:00Z", latest, published, 15, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := newPatchCheckNode(t)
			n.running(t, tc.running)
			run := n.run(t, tc.now)
			assertResultShape(t, run, tc.now)
			assertVerdict(t, run, tc.verdict)
			assertValues(t, "k3s", run.part(t, "k3s"), wantK3s(tc.running, latest, tc.firstNewer, tc.publishedAt, tc.days, tc.verdict))
			assertValues(t, "os", run.part(t, "os"), wantPatchedOS(n.refreshedAt(t, tc.now)))
			for _, path := range []string{k3sChannelsPath, k3sReleasesPath} {
				got := n.feeds.requests(path)
				failIf(t, got != 1, "the check requested %s %d times, want once", path, got)
			}
		})
	}
}

func TestPatchCheck_ReadsTheRunningK3sFromTheNodeAndFallsBackToK3sVersion(t *testing.T) {
	t.Parallel()
	const now = "2026-10-08T03:10:00Z"
	t.Run("the node answers", func(t *testing.T) {
		t.Parallel()
		n := newPatchCheckNode(t)
		n.k3s = newFakeK3s(t, k3sAnswer(readNodes, nodesRunning("v1.36.5+k3s1")),
			k3sVersion("k3s version v1.36.3+k3s1 (2d0f82fa)\ngo version go1.24.6\n", "", 0)).path

		run := n.run(t, now)

		running := run.part(t, "k3s")["running"]
		failIf(t, running != "v1.36.5+k3s1", "k3s.running = %#v; want the node's kubelet version v1.36.5+k3s1 over k3s --version", running)
	})
	t.Run("the API is not up", func(t *testing.T) {
		t.Parallel()
		n := newPatchCheckNode(t)
		k3s := newFakeK3s(t, k3sFailing(readNodes, 1, k3sRefused+"\n"),
			k3sVersion("k3s version v1.36.5+k3s1 (2d0f82fa)\ngo version go1.24.6\n", "", 0))
		n.k3s = k3s.path

		run := n.run(t, now)

		assertVerdict(t, run, "pass")
		assertValues(t, "k3s", run.part(t, "k3s"), wantK3s("v1.36.5+k3s1", "v1.36.5+k3s1", nil, nil, 0, "pass"))
		if !slices.ContainsFunc(k3s.argvs(t), func(a []string) bool {
			return slices.Equal(a, []string{"--version"}) || slices.Equal(a, []string{"-v"}) || slices.Equal(a, []string{"version"})
		}) {
			t.Errorf("k3s never ran --version; it ran with %q", k3s.calls(t))
		}
	})
}

func TestPatchCheck_NeverPassesWhenItCannotReadK3sOrItsReleases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, n *patchCheckNode) []scriptRunOption
	}{
		{"the channels answer 503", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.feeds.answer(k3sChannelsPath, http.StatusServiceUnavailable, "")
			return nil
		}},
		{"GitHub answers 403 rate limited", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.feeds.answer(k3sReleasesPath, http.StatusForbidden, `{"message": "API rate limit exceeded for 203.0.113.7."}`)
			return nil
		}},
		{"the channels are not JSON", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.feeds.answer(k3sChannelsPath, http.StatusOK, "<html><body>maintenance</body></html>")
			return nil
		}},
		{"the releases are not JSON", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.feeds.answer(k3sReleasesPath, http.StatusOK, "tag_name: v1.36.5+k3s1")
			return nil
		}},
		{"the releases are not a list", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.feeds.answer(k3sReleasesPath, http.StatusOK, `{"message": "Not Found"}`)
			return nil
		}},
		{"the running minor has no channel", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.running(t, "v1.38.0+k3s1")
			return nil
		}},
		{"the channels are unreachable", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			return []scriptRunOption{withEnv(patchCheckChannelsURLEnv, closedEndpoint(t))}
		}},
		{"k3s answers nothing", func(t *testing.T, n *patchCheckNode) []scriptRunOption {
			n.k3s = newFakeTool(t, "k3s", "", k3sRefused+"\n", 1).path
			return nil
		}},
	}
	for _, tc := range cases {
		name := tc.name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n := newPatchCheckNode(t)
			opts := tc.setup(t, n)
			const now = "2026-10-08T03:10:00Z"

			run := n.run(t, now, opts...)

			k3sVerdict := run.part(t, "k3s")["verdict"]
			failIf(t, k3sVerdict != "unknown", "k3s.verdict = %#v when %s; want unknown:\n%s", k3sVerdict, name, run.raw)
			assertVerdict(t, run, "unknown")
			osVerdict := run.part(t, "os")["verdict"]
			failIf(t, osVerdict != "pass", "os.verdict = %#v when %s; want pass for a patched OS whatever k3s's reads did", osVerdict, name)
		})
	}
}

func TestPatchCheck_ReportsTheRunningOSAndTheNewestInstalledKernel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		boot   func(t *testing.T) string
		latest any
	}{
		{"three kernels installed", func(t *testing.T) string {
			return bootDirWith(t, "vmlinuz-6.8.0-85-generic",
				"vmlinuz-6.8.0-9-generic", "vmlinuz-6.8.0-71-generic", "vmlinuz-6.8.0-85-generic",
				"initrd.img-6.8.0-85-generic", "config-6.8.0-90-generic", "System.map-6.8.0-90-generic")
		}, "6.8.0-85-generic"},
		{"no kernel in /boot", func(t *testing.T) string { return t.TempDir() }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := newPatchCheckNode(t)
			n.bootDir = tc.boot(t)

			run := n.run(t, "2026-10-08T03:10:00Z")

			osPart := run.part(t, "os")
			running := osPart["running"]
			failIf(t, running != runningOS, "os.running with %s = %#v; want %q", tc.name, running, runningOS)
			latestKernel := osPart["latestKernel"]
			failIf(t, latestKernel != tc.latest, "os.latestKernel with %s = %#v; want %#v", tc.name, latestKernel, tc.latest)
		})
	}
}

func TestPatchCheck_ListsThePendingUpgradesFromASimulatedDistUpgrade(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	n.aptGet = newFakeTool(t, "apt-get", cannedAptPending, "", 0)
	const now = "2026-10-08T03:10:00Z"
	run := n.run(t, now)
	assertVerdict(t, run, "pass")
	assertValues(t, "os", run.part(t, "os"), map[string]any{
		"running": runningOS, "latestKernel": runningKernel, "pendingUpgrades": wantAptPending,
		"rebootRequired": false, "listsRefreshedAt": n.refreshedAt(t, now),
		"behindSince": now, "behindDays": float64(0), "verdict": "pass",
	})
	runs := n.aptGet.runs(t)
	fatalIf(t, len(runs) == 0, "the check never ran apt-get")
	simulated := []string{"-s", "--simulate", "--just-print", "--dry-run", "--recon", "--no-act"}
	for _, args := range runs {
		failIf(t, slices.Contains(args, "update"), "the check ran apt-get %q, want it never to update the package lists itself", args)
		failIf(t, !slices.Contains(args, "dist-upgrade") || !slices.ContainsFunc(args, func(a string) bool { return slices.Contains(simulated, a) }), "the check ran apt-get %q, want only a simulated dist-upgrade", args)
	}
}

func TestPatchCheck_BoundsThePendingUpgrades(t *testing.T) {
	t.Parallel()
	var lines []string
	for i := range 500 {
		lines = append(lines, fmt.Sprintf("Inst package-%04d-%s [1.0.%d-0ubuntu1] (1.0.%d-0ubuntu2 Ubuntu:24.04/noble-updates [amd64])", i, strings.Repeat("p", 30), i, i))
	}
	n := newPatchCheckNode(t)
	n.aptGet = newFakeTool(t, "apt-get", aptSimulationHeader+strings.Join(lines, "\n")+"\n", "", 0)
	run := n.run(t, "2026-10-08T03:10:00Z")
	pending, ok := run.part(t, "os")["pendingUpgrades"].([]any)
	fatalIf(t, !ok || len(pending) == 0, "os.pendingUpgrades = %#v, want the first of the 500 upgrades", run.part(t, "os")["pendingUpgrades"])
	n2 := len(mustJSON(pending))
	failIf(t, n2 > pendingUpgradesLimit, "os.pendingUpgrades is %d bytes of JSON text, want at most %d", n2, pendingUpgradesLimit)
	for i, e := range pending {
		want := map[string]any{
			"package":   fmt.Sprintf("package-%04d-%s", i, strings.Repeat("p", 30)),
			"installed": fmt.Sprintf("1.0.%d-0ubuntu1", i),
			"candidate": fmt.Sprintf("1.0.%d-0ubuntu2", i),
		}
		if m, _ := e.(map[string]any); !mapsEqualAny(m, want) {
			t.Errorf("os.pendingUpgrades[%d] = %#v, want the %dth upgrade whole, %v", i, e, i+1, want)
			break
		}
	}
	failIf(t, len(run.raw) > patchCheckFileLimit, "%s is %d bytes, want at most %d so the report carries it whole", patchCheckFile, len(run.raw), patchCheckFileLimit)
}

func mapsEqualAny(a, b map[string]any) bool { return mustJSON(a) == mustJSON(b) }

func TestPatchCheck_RecordsAPendingReboot(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	n.rebootRequired = rebootSentinel(t, time.Date(2026, 10, 8, 1, 30, 21, 0, time.UTC), "linux-image-6.8.0-85-generic\n")
	const now = "2026-10-08T03:10:00Z"
	run := n.run(t, now)
	assertVerdict(t, run, "pass")
	assertValues(t, "os", run.part(t, "os"), map[string]any{
		"running": runningOS, "latestKernel": runningKernel, "pendingUpgrades": []any{},
		"rebootRequired": true, "listsRefreshedAt": n.refreshedAt(t, now),
		"behindSince": now, "behindDays": float64(0), "verdict": "pass",
	})
}

func TestPatchCheck_KeepsWhenTheOSFellBehindAndFailsFromTheFifteenthDay(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	pending := newFakeTool(t, "apt-get", cannedAptPending, "", 0)
	patched := newFakeTool(t, "apt-get", cannedAptNothingPending, "", 0)
	steps := []struct {
		now         string
		aptGet      fakeTool
		behindSince any
		days        int
		verdict     string
	}{
		{"2026-09-20T03:10:00Z", pending, "2026-09-20T03:10:00Z", 0, "pass"},
		{"2026-10-04T03:10:00Z", pending, "2026-09-20T03:10:00Z", 14, "pass"},
		{"2026-10-05T03:10:00Z", pending, "2026-09-20T03:10:00Z", 15, "fail"},
		{"2026-10-05T04:10:00Z", patched, nil, 0, "pass"},
		{"2026-10-06T03:10:00Z", pending, "2026-10-06T03:10:00Z", 0, "pass"},
	}
	for i, s := range steps {
		n.aptGet = s.aptGet

		run := n.run(t, s.now)

		osPart := run.part(t, "os")
		behindSince := osPart["behindSince"]
		failIf(t, behindSince != s.behindSince, "check %d at %s: os.behindSince = %#v; want %#v", i+1, s.now, behindSince, s.behindSince)
		behindDays := osPart["behindDays"]
		failIf(t, behindDays != float64(s.days), "check %d at %s: os.behindDays = %#v; want %d", i+1, s.now, behindDays, s.days)
		verdict := osPart["verdict"]
		failIf(t, verdict != s.verdict, "check %d at %s: os.verdict = %#v; want %s", i+1, s.now, verdict, s.verdict)
		// k3s is on its channel's latest throughout, so the OS decides.
		assertVerdict(t, run, s.verdict)
	}
}

func TestPatchCheck_NeverPassesWhenAptGetFails(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	n.aptGet = newFakeTool(t, "apt-get", "", "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 2211 (unattended-upgr)\n", 100)

	run := n.run(t, "2026-10-08T03:10:00Z")

	verdict := run.part(t, "os")["verdict"]
	failIf(t, verdict != "unknown", "os.verdict = %#v after apt-get failed; want unknown:\n%s", verdict, run.raw)
	assertVerdict(t, run, "unknown")
}

func TestPatchCheck_UsesTheClockWithoutAnOverride(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	start := time.Now()
	run := n.run(t, "")
	end := time.Now()
	assertResultShape(t, run, "")
	assertUTCWithin(t, run.result["checkedAt"], start, end)
}

func TestPatchCheck_TheNextReportCarriesWhatTheCheckWrote(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	n.running(t, "v1.36.3+k3s1")
	n.aptGet = newFakeTool(t, "apt-get", cannedAptPending, "", 0)
	run := n.run(t, "2026-10-08T03:10:00Z")
	assertVerdict(t, run, "fail")
	fatalIf(t, len(run.raw) > patchCheckFileLimit, "%s is %d bytes, want at most %d so the report carries it whole", patchCheckFile, len(run.raw), patchCheckFileLimit)

	got := patchingFields(t, newReportRig(t, withEnvVar(reportStateDirEnv, n.stateDir)).send())["check"]
	carried, _ := decodeAny(t, "patching.check", got).(map[string]any)
	failIf(t, carried == nil || !mapsEqualAny(carried, run.result), "patching.check = %s\nwant what the check wrote, %s", got, run.raw)
}

func TestPatchCheck_OSIsUnknownWithoutAListsRefreshStamp(t *testing.T) {
	t.Parallel()
	n := newPatchCheckNode(t)
	n.noStamp = true

	run := n.run(t, "2026-10-08T03:10:00Z")

	osPart := run.part(t, "os")
	refreshedAt, ok := osPart["listsRefreshedAt"]
	failIf(t, !ok || refreshedAt != nil, "os.listsRefreshedAt = %#v (present %v) without the stamp; want null", refreshedAt, ok)
	verdict := osPart["verdict"]
	failIf(t, verdict != "unknown", "os.verdict = %#v without the update stamp; want unknown:\n%s", verdict, run.raw)
	assertVerdict(t, run, "unknown")
}

func TestPatchCheck_OSFailsOnPackageListsMoreThan14DaysStale(t *testing.T) {
	t.Parallel()
	const now = "2026-10-08T03:10:00Z"
	for _, tc := range []struct {
		name    string
		age     time.Duration
		verdict string
	}{
		{"refreshed an hour ago", time.Hour, "pass"},
		{"refreshed 14 days and 23 hours ago", 14*24*time.Hour + 23*time.Hour, "pass"},
		{"refreshed 15 days ago", 15 * 24 * time.Hour, "fail"},
		{"refreshed 90 days ago", 90 * 24 * time.Hour, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := newPatchCheckNode(t)
			n.stampAge = tc.age

			run := n.run(t, now)

			osPart := run.part(t, "os")
			refreshedAt, want := osPart["listsRefreshedAt"], n.refreshedAt(t, now)
			failIf(t, refreshedAt != want, "os.listsRefreshedAt with lists %s = %#v; want the stamp's mtime %s", tc.name, refreshedAt, want)
			pending := osPart["pendingUpgrades"]
			failIf(t, !reflect.DeepEqual(pending, []any{}), "os.pendingUpgrades with lists %s = %#v; want none, so only the lists' age decides", tc.name, pending)
			verdict := osPart["verdict"]
			failIf(t, verdict != tc.verdict, "os.verdict with lists %s = %#v; want %s:\n%s", tc.name, verdict, tc.verdict, run.raw)
			// k3s is on its channel's latest, so the OS decides the check.
			assertVerdict(t, run, tc.verdict)
		})
	}
}

func TestPatchCheck_NeverStoresAnUnvalidatedK3sAnswer(t *testing.T) {
	t.Parallel()
	junk := strings.Repeat("Z", 10240)
	cases := []struct {
		name, running string
		setup         func(n *patchCheckNode)
		field         string
	}{
		{"a channel latest of 10 KB", "v1.36.5+k3s1", func(n *patchCheckNode) {
			n.feeds.answer(k3sChannelsPath, http.StatusOK, strings.Replace(cannedK3sChannels, `"latest": "v1.36.5+k3s1"`, `"latest": "`+junk+`"`, 1))
		}, "latest"},
		{"a published_at of 10 KB", "v1.36.4+k3s1", func(n *patchCheckNode) {
			n.feeds.answer(k3sReleasesPath, http.StatusOK, mustJSON([]any{
				k3sRelease("v1.36.5+k3s1", false, junk),
				k3sRelease("v1.36.4+k3s1", false, "2026-08-27T15:53:55Z"),
			}))
		}, "firstNewerPublishedAt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := newPatchCheckNode(t)
			n.running(t, tc.running)
			tc.setup(n)

			run := n.run(t, "2026-10-08T03:10:00Z")

			failIf(t, len(run.raw) > patchCheckFileLimit, "%s with %s is %d bytes; want at most %d", patchCheckFile, tc.name, len(run.raw), patchCheckFileLimit)
			k3s := run.part(t, "k3s")
			verdict := k3s["verdict"]
			failIf(t, verdict != "unknown", "k3s.verdict with %s = %#v; want unknown for an answer that does not parse", tc.name, verdict)
			kept := k3s[tc.field]
			failIf(t, kept != nil, "k3s.%s with %s = %q; want null, since an answer that does not parse is never kept", tc.field, tc.name, truncate(fmt.Sprint(kept), 80))
			failIf(t, strings.Contains(string(run.raw), strings.Repeat("Z", 200)), "%s with %s keeps the junk answer verbatim", patchCheckFile, tc.name)
			assertVerdict(t, run, "unknown")
		})
	}
}
