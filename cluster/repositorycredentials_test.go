package cluster

// The seed gives every new cluster the repository-credentials Application, which syncs the repository Secrets and
// grants the app slices commit while ignoring only the token the repository-token refresh patches.

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	seedRepositoryCredentialsPath       = "cluster/repository-credentials.yaml"
	seedRepositoryCredentialsReadmePath = "repository-credentials/README.md"
)

func repositoryCredentialsApp(t *testing.T, v Versions) map[string]any {
	t.Helper()
	return testutil.YamlMap(t, seedRepositoryCredentialsPath, seedFiles(t, v)[seedRepositoryCredentialsPath])
}

func TestRenderSeed_RepositoryCredentialsSyncsTheSlicesDirectoryFromTheClusterRepository(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		app := repositoryCredentialsApp(t, v)

		testutil.AssertPaths(t, "the repository-credentials Application", app, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata.name": "repository-credentials", "metadata.namespace": "argocd",
			"spec.project":        "default",
			"spec.source.repoURL": testutil.FixtureRepoURL, "spec.source.path": "repository-credentials", "spec.source.targetRevision": "HEAD",
			"spec.destination.server": inClusterAPI, "spec.destination.namespace": "argocd",
		})
	})
}

func TestRenderSeed_RepositoryCredentialsPrunesSelfHealsAndAllowsAnEmptyDirectory(t *testing.T) {
	app := repositoryCredentialsApp(t, PinnedVersions)

	automated, ok := testutil.Dig(app, "spec", "syncPolicy", "automated").(map[string]any)
	want := map[string]any{"prune": true, "selfHeal": true, "allowEmpty": true}
	testutil.FailIf(t, !ok || !reflect.DeepEqual(automated, want), "spec.syncPolicy.automated = %#v, want exactly %v, so the last slice's removal prunes its Secret and grant", testutil.Dig(app, "spec", "syncPolicy", "automated"), want)
	opts := stringsOf(t, "spec.syncPolicy.syncOptions", testutil.Dig(app, "spec", "syncPolicy", "syncOptions"))
	testutil.FailIf(t, !slices.Equal(opts, []string{"RespectIgnoreDifferences=true"}), "spec.syncPolicy.syncOptions = %q, want only RespectIgnoreDifferences=true, so a sync never writes the ignored token back", opts)
}

func TestRenderSeed_RepositoryCredentialsIgnoresOnlyTheSecretsPassword(t *testing.T) {
	app := repositoryCredentialsApp(t, PinnedVersions)

	rules, ok := testutil.Dig(app, "spec", "ignoreDifferences").([]any)
	testutil.FatalIf(t, !ok || len(rules) != 1, "spec.ignoreDifferences = %#v, want exactly one rule", testutil.Dig(app, "spec", "ignoreDifferences"))
	rule, ok := rules[0].(map[string]any)
	testutil.FatalIf(t, !ok, "spec.ignoreDifferences[0] = %#v, want a mapping", rules[0])
	testutil.FailIf(t, rule["group"] != "" || rule["kind"] != "Secret" || rule["namespace"] != "argocd", "the ignore rule names group %q, kind %v and namespace %v, want the core group's Secrets in argocd", rule["group"], rule["kind"], rule["namespace"])
	_, named := rule["name"]
	testutil.FailIf(t, named, "the ignore rule names the Secret %v, want it to cover every slice's Secret", rule["name"])
	pointers := stringsOf(t, "the ignore rule's jsonPointers", rule["jsonPointers"])
	testutil.FailIf(t, !slices.Equal(pointers, []string{"/data/password"}), "the ignore rule's jsonPointers = %q, want only /data/password, so self-heal reverts a changed url, type, username or project", pointers)
	for key := range rule {
		testutil.FailIf(t, !slices.Contains([]string{"group", "kind", "namespace", "jsonPointers"}, key), "the ignore rule carries %q, want only group, kind, namespace and jsonPointers", key)
	}
}

func TestRenderSeed_NoSeededApplicationStartsWithTheSlicePrefix(t *testing.T) {
	eachVersions(t, func(t *testing.T, v Versions) {
		apps, _ := seedCustomResources(t, seedFiles(t, v))

		testutil.FailIf(t, apps["repository-credentials"] == nil, "the seed holds no repository-credentials Application among %d Applications", len(apps))
		for name := range apps {
			testutil.FailIf(t, strings.HasPrefix(name, "app-"), "the seed holds the Application %q, and every name starting with app- belongs to an app slice", name)
		}
	})
}

func TestRenderSeed_KeepsTheRepositoryCredentialsDirectoryWithAReadmeArgoCDNeverApplies(t *testing.T) {
	files := seedFiles(t, PinnedVersions)

	readme := files[seedRepositoryCredentialsReadmePath]
	testutil.FailIf(t, !strings.HasPrefix(readme, "# "), "%s is %q, want a Markdown README that keeps the directory in Git", seedRepositoryCredentialsReadmePath, readme)
	for path := range files {
		if dir, _, _ := strings.Cut(path, "/"); dir != "repository-credentials" {
			continue
		}
		for _, ext := range []string{".yaml", ".yml", ".json"} {
			testutil.FailIf(t, strings.HasSuffix(path, ext), "the seed writes %s, which the repository-credentials Application would apply", path)
		}
	}
}

func TestRenderSeed_RefusesARepositoryURLThatIsNotHTTPS(t *testing.T) {
	for _, url := range []string{"", "http://github.com/acme/orbitdemo-cluster", "git@github.com:acme/orbitdemo-cluster.git", "https://github.com/acme/orbit demo"} {
		_, err := RenderSeed(PinnedVersions, testutil.FixtureIngressIPv4, url)

		testutil.FailIf(t, err == nil || !strings.Contains(err.Error(), "repository URL"), "RenderSeed with repository URL %q = %v, want a refusal naming the repository URL", url, err)
	}
}
