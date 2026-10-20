package cluster

// localpvlvm_test.go pins the storage a dedicated server's seed carries.

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/mitstack-eu/k3s-cluster-kit/testutil"
)

const (
	// wantLocalPVLVMTree is what `git rev-parse v0.5.0:localpv-lvm` answers in mitstack-eu/cluster-bases.
	wantLocalPVLVMTree        = "dd8e9a49c4d112cea2871198afc8e945544bf295"
	wantLocalPVLVMApplication = "cluster/localpv-lvm.yaml"
	wantLocalPVLVMDir         = "cluster-bases/localpv-lvm"
)

func localPVLVMFiles(t *testing.T, seed map[string]string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for p, content := range seed {
		if rest, ok := strings.CutPrefix(p, wantLocalPVLVMDir+"/"); ok {
			testutil.FatalIf(t, strings.Contains(rest, "/"), "the seed writes %s in a subdirectory of %s, want the component's files flat as cluster-bases holds them", p, wantLocalPVLVMDir)
			files[rest] = content
		}
	}
	return files
}

func componentDocs(t *testing.T, seed map[string]string) []map[string]any {
	t.Helper()
	files := localPVLVMFiles(t, seed)
	testutil.FatalIf(t, len(files) == 0, "a dedicated server's seed writes nothing under %s/", wantLocalPVLVMDir)
	var docs []map[string]any
	for _, name := range slices.Sorted(maps.Keys(files)) {
		docs = append(docs, testutil.YamlDocs(t, wantLocalPVLVMDir+"/"+name, files[name])...)
	}
	return docs
}

// podImages lists the image of every container and init container in a workload's pod template.
func podImages(doc map[string]any) []string {
	var images []string
	for _, field := range []string{"initContainers", "containers"} {
		list, _ := testutil.Dig(doc, "spec", "template", "spec", field).([]any)
		for _, c := range list {
			if image, ok := testutil.Dig(c, "image").(string); ok {
				images = append(images, image)
			}
		}
	}
	return images
}

func TestSeed_ADedicatedServersRepositoryCarriesLocalPVLVMAsTheClusterBasesReleaseHoldsIt(t *testing.T) {
	files := localPVLVMFiles(t, dedicatedSeed(t))

	testutil.FatalIf(t, len(files) == 0, "a dedicated server's seed writes nothing under %s/, want cluster-bases %s's localpv-lvm directory", wantLocalPVLVMDir, wantClusterBasesTag)
	got := gitTreeID(files)
	testutil.FailIf(t, got != wantLocalPVLVMTree, "the seed's %s/ is git tree %s holding %v, want %s, the tree of localpv-lvm at cluster-bases %s", wantLocalPVLVMDir, got, slices.Sorted(maps.Keys(files)), wantLocalPVLVMTree, wantClusterBasesTag)
}

func TestSeed_ADedicatedServersRepositorySyncsLocalPVLVMIntoKubeSystemAtTheClusterBasesTag(t *testing.T) {
	seed := dedicatedSeed(t)

	content, ok := seed[wantLocalPVLVMApplication]
	testutil.FatalIf(t, !ok, "a dedicated server's seed writes no %s", wantLocalPVLVMApplication)
	app := testutil.YamlMap(t, wantLocalPVLVMApplication, content)
	for _, c := range []struct {
		path []string
		want any
	}{
		{[]string{"kind"}, "Application"},
		{[]string{"metadata", "name"}, "localpv-lvm"},
		{[]string{"metadata", "namespace"}, "argocd"},
		{[]string{"metadata", "annotations", "mitstack.dev/cluster-bases-tag"}, wantClusterBasesTag},
		{[]string{"spec", "source", "repoURL"}, testutil.FixtureRepoURL},
		{[]string{"spec", "source", "path"}, wantLocalPVLVMDir},
		{[]string{"spec", "source", "targetRevision"}, "HEAD"},
		{[]string{"spec", "destination", "server"}, "https://kubernetes.default.svc"},
		{[]string{"spec", "destination", "namespace"}, "kube-system"},
		{[]string{"spec", "syncPolicy", "automated", "prune"}, true},
		{[]string{"spec", "syncPolicy", "automated", "selfHeal"}, true},
	} {
		got := testutil.Dig(app, c.path...)
		testutil.FailIf(t, got != c.want, "%s %s = %#v, want %#v", wantLocalPVLVMApplication, strings.Join(c.path, "."), got, c.want)
	}
}

func TestSeed_ADedicatedServersLocalPVLVMNamesEveryImageByDigest(t *testing.T) {
	docs := componentDocs(t, dedicatedSeed(t))

	var images []string
	for _, doc := range docs {
		images = append(images, podImages(doc)...)
	}
	testutil.FailIf(t, len(images) < 2, "the component's workloads run %d images, want at least the controller's and the node plugin's", len(images))
	for _, image := range images {
		testutil.FailIf(t, !imageByDigest.MatchString(image), "the component runs image %q, want it named by its sha256 digest", image)
	}
}

func TestSeed_ADedicatedServersDefaultStorageClassIsLocalPVLVMOnVolumeGroupVg0(t *testing.T) {
	docs := componentDocs(t, dedicatedSeed(t))

	var defaults []map[string]any
	for _, doc := range docs {
		if doc["kind"] == "StorageClass" && testutil.Dig(doc, "metadata", "annotations", "storageclass.kubernetes.io/is-default-class") == "true" {
			defaults = append(defaults, doc)
		}
	}
	testutil.FatalIf(t, len(defaults) != 1, "the component holds %d default storage classes, want exactly one", len(defaults))
	sc := defaults[0]
	testutil.FailIf(t, sc["provisioner"] != "local.csi.openebs.io", "the default storage class's provisioner = %#v, want local.csi.openebs.io, LocalPV-LVM's CSI driver", sc["provisioner"])
	testutil.FailIf(t, testutil.Dig(sc, "parameters", "storage") != "lvm", "the default storage class's parameters.storage = %#v, want lvm", testutil.Dig(sc, "parameters", "storage"))
	testutil.FailIf(t, testutil.Dig(sc, "parameters", "volgroup") != "vg0", "the default storage class's parameters.volgroup = %#v, want vg0, the volume group the install leaves free", testutil.Dig(sc, "parameters", "volgroup"))
	drivers := 0
	for _, doc := range docs {
		if doc["kind"] == "CSIDriver" && testutil.Dig(doc, "metadata", "name") == "local.csi.openebs.io" {
			drivers++
		}
	}
	testutil.FailIf(t, drivers != 1, "the component registers %d CSIDriver local.csi.openebs.io, want one, so the storage class has a driver", drivers)
}

func TestSeed_ADedicatedServersRepositoryRunsNeitherLocalPathNorLonghorn(t *testing.T) {
	seed := dedicatedSeed(t)

	for p, content := range seed {
		for _, banned := range []string{"rancher.io/local-path", "local-path-provisioner", "longhorn"} {
			testutil.FailIf(t, strings.Contains(strings.ToLower(content), banned), "the dedicated seed's %s names %q, which ADR 0089 rejects", p, banned)
		}
	}
}
