package cluster

// localpvlvm_test.go pins the storage a dedicated server's seed carries.

import (
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

func TestSeed_ADedicatedServersRepositorySyncsLocalPVLVMIntoKubeSystemAtTheClusterBasesTag(t *testing.T) {
	seed := dedicatedSeed(t)

	content, ok := seed[wantLocalPVLVMApplication]
	testutil.FatalIf(t, !ok, "a dedicated server's seed writes no %s", wantLocalPVLVMApplication)
	app := testutil.YamlMap(t, wantLocalPVLVMApplication, content)

	testutil.AssertPaths(t, wantLocalPVLVMApplication, app, map[string]any{
		"kind": "Application", "metadata.name": "localpv-lvm", "metadata.namespace": "argocd",
		"spec.source.repoURL": testutil.FixtureRepoURL, "spec.source.path": wantLocalPVLVMDir, "spec.source.targetRevision": "HEAD",
		"spec.destination.server": "https://kubernetes.default.svc", "spec.destination.namespace": "kube-system",
		"spec.syncPolicy.automated.prune": true, "spec.syncPolicy.automated.selfHeal": true,
	})
	tag := testutil.Dig(app, "metadata", "annotations", "mitstack.dev/cluster-bases-tag")
	testutil.FailIf(t, tag != wantClusterBasesTag, "%s's cluster-bases-tag annotation = %#v, want %s", wantLocalPVLVMApplication, tag, wantClusterBasesTag)
}

func TestSeed_ADedicatedServersLocalPVLVMNamesEveryImageByDigest(t *testing.T) {
	docs := docsUnder(t, dedicatedSeed(t), wantLocalPVLVMDir)

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
	docs := docsUnder(t, dedicatedSeed(t), wantLocalPVLVMDir)

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
